import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from flask import request, jsonify, session, Response, stream_with_context
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from traffic_platform.train_test.main import analysis
from traffic_platform.web_platform import app, mongo
from traffic_platform.web_platform.capture_service import capture_service

import json
import shutil
import time as time_module
import warnings

import numpy as np
from bson import ObjectId
from bson.errors import InvalidId

from traffic_platform.train_test.get_feature import GetFeature
from traffic_platform.train_test.main import predicts, run, run_with_extra_pcaps

PROTOCOL_KEYS = ('TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'Other')


def _train_test_dir():
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'train_test',
    )


def _model_pkl_path():
    return os.path.join(_train_test_dir(), 'model.pkl')


def _model_archive_dir():
    return os.path.join(_train_test_dir(), 'model_archive')


def _archive_model_snapshot_for_run(run_id: str):
    """将当前 model.pkl 复制为 model_archive/model_<run_id>.pkl，返回相对 train_test 的路径；无源文件则返回 None。"""
    train_root = _train_test_dir()
    src = _model_pkl_path()
    if not os.path.isfile(src):
        return None
    archive = _model_archive_dir()
    os.makedirs(archive, exist_ok=True)
    rel = os.path.join('model_archive', f'model_{run_id}.pkl')
    dst = os.path.join(train_root, rel)
    shutil.copy2(src, dst)
    return rel.replace('\\', '/')


def _resolved_model_archive_file(rel_path: str):
    """将 DB 中的相对路径解析为真实文件路径，且必须落在 model_archive 下。"""
    if not rel_path or not isinstance(rel_path, str):
        return None
    train_root = os.path.realpath(_train_test_dir())
    root_archive = os.path.realpath(_model_archive_dir())
    full = os.path.realpath(os.path.join(train_root, rel_path))
    try:
        if os.path.commonpath([root_archive, full]) != root_archive:
            return None
    except ValueError:
        return None
    return full if os.path.isfile(full) else None

CAPTURE_FEATURE_COLUMNS = [
    'len_mean', 'len_std', 'time_mean', 'time_std', 'num_unknown',
    'IP', 'UDP', 'DNS ANS', 'DNS Qry', 'IPV6', 'ICMPv6', 'TLS',
]


def _serialize_detection_doc(doc):
    out = {}
    for k, v in doc.items():
        if k == '_id':
            out['id'] = str(v)
        elif k == 'created_at' and hasattr(v, 'isoformat'):
            out['created_at'] = v.isoformat()
        else:
            out[k] = v
    return out


USER_STATUS_ACTIVE = 'active'
USER_STATUS_BLOCKED = 'blocked'


def _user_doc_by_session():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        return mongo.db.users.find_one({'_id': ObjectId(uid)})
    except (InvalidId, TypeError):
        return None


def _require_login_active():
    """已登录且账号未封禁。"""
    if not session.get('logged_in'):
        return jsonify({'error': '请先登录'}), 401
    user = _user_doc_by_session()
    if not user:
        session.clear()
        return jsonify({'error': '请重新登录'}), 401
    if user.get('status', USER_STATUS_ACTIVE) == USER_STATUS_BLOCKED:
        session.clear()
        return jsonify({'error': '账号已被封禁'}), 403
    return None


def _require_admin():
    """管理员且未封禁（抓包协议分析、用户管理等）。"""
    if not session.get('logged_in'):
        return jsonify({'error': '请先登录'}), 401
    user = _user_doc_by_session()
    if not user:
        session.clear()
        return jsonify({'error': '请重新登录'}), 401
    if user.get('status', USER_STATUS_ACTIVE) == USER_STATUS_BLOCKED:
        session.clear()
        return jsonify({'error': '账号已被封禁'}), 403
    if user.get('role', 'user') != 'admin':
        return jsonify({'error': '需要管理员权限'}), 403
    return None


## ===================用户注册/登录/注销 API====================================

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400

    user = mongo.db.users.find_one({'username': username})
    if user is None:
        return jsonify({'error': '用户名不存在'}), 401
    elif not check_password_hash(user['password'], password):
        return jsonify({'error': '密码错误'}), 401
    elif user.get('status', USER_STATUS_ACTIVE) == USER_STATUS_BLOCKED:
        return jsonify({'error': '账号已被封禁，请联系管理员'}), 403
    else:
        session['logged_in'] = True
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['role'] = user.get('role', 'user')
        return jsonify({
            'message': '登录成功',
            'username': user['username'],
            'role': user.get('role', 'user'),
            'status': user.get('status', USER_STATUS_ACTIVE),
        }), 200


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    role = data.get('role', 'user')  # 默认为普通用户

    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400

    if len(username) < 3 or len(username) > 10:
        return jsonify({'error': '用户名长度应为3-10个字符'}), 400

    if len(password) < 6 or len(password) > 16:
        return jsonify({'error': '密码长度应为6-16个字符'}), 400

    if password != confirm_password:
        return jsonify({'error': '两次输入的密码不一致'}), 400

    # 验证角色
    if role not in ['admin', 'user']:
        return jsonify({'error': '无效的角色'}), 400

    existing_user = mongo.db.users.find_one({'username': username})
    if existing_user:
        return jsonify({'error': '用户名已存在'}), 400

    # 检查是否已存在用户，第一个注册的用户默认为 admin
    user_count = mongo.db.users.count_documents({})
    user_role = 'admin' if user_count == 0 else role

    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({
        'username': username,
        'password': hashed_password,
        'role': user_role,
        'status': USER_STATUS_ACTIVE,
    })

    return jsonify({'message': '注册成功', 'role': user_role}), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return jsonify({'message': '已退出登录'}), 200


@app.route('/api/check-session', methods=['GET'])
def check_session():
    if not session.get('logged_in'):
        return jsonify({'logged_in': False}), 200
    user = _user_doc_by_session()
    if not user or user.get('status', USER_STATUS_ACTIVE) == USER_STATUS_BLOCKED:
        session.clear()
        return jsonify({'logged_in': False}), 200
    return jsonify({
        'logged_in': True,
        'username': user.get('username'),
        'role': user.get('role', 'user'),
        'status': user.get('status', USER_STATUS_ACTIVE),
        'user_id': str(user['_id']),
    }), 200


## ===================文件检测 API====================================

@app.route('/api/detection', methods=['POST'])
def detection():
    denied = _require_login_active()
    if denied:
        return denied

    try:
        f = request.files.get('file')
        if not f:
            return jsonify({'error': '没有文件'}), 400
            
        ftype = secure_filename(f.filename).split('.')[-1]
        if ftype != 'pcap':
            return jsonify({'error': '请上传 .pcap 文件'}), 400
        
        pcap_save_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
        csv_save_path = os.path.join(app.config['UPLOAD_FOLDER'], 'result.csv')
        f.save(pcap_save_path)
        
        import time
        start_time = time.time()
        
        # 执行检测
        result = analysis(pcap_save_path, csv_save_path, num_epoch=5, num_ev=20)
        
        elapsed_time = round(time.time() - start_time, 2)
        
        # 统计 pcap 文件信息
        try:
            from scapy.all import rdpcap
            from scapy.layers.inet import TCP, UDP, ICMP
            packets = rdpcap(pcap_save_path)
            total_packets = len(packets)
            
            # 统计协议
            tcp_count = 0
            udp_count = 0
            http_count = 0
            icmp_count = 0
            arp_count = 0
            other_count = 0
            
            for p in packets:
                if p.haslayer(TCP):
                    tcp_count += 1
                    tcp_layer = p[TCP]
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        http_count += 1
                elif p.haslayer(UDP):
                    udp_count += 1
                elif p.haslayer(ICMP):
                    icmp_count += 1
                elif p.haslayer('ARP'):
                    arp_count += 1
                else:
                    other_count += 1
            
            protocols = {
                'TCP': tcp_count,
                'UDP': udp_count,
                'ICMP': icmp_count,
                'ARP': arp_count,
                'HTTP': http_count,
                'Other': other_count
            }
            print(f"协议统计: 总数={total_packets}, TCP={tcp_count}, UDP={udp_count}, ICMP={icmp_count}, ARP={arp_count}, Other={other_count}")
        except Exception as e:
            print(f"协议统计出错: {e}")
            import traceback
            traceback.print_exc()
            total_packets = 0
            protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'HTTP': 0, 'Other': 0}

        safe_label = '安全' if result else '危险'
        filename_stored = secure_filename(f.filename)
        detection_doc = {
            'username': session.get('username'),
            'user_id': session.get('user_id'),
            'filename': filename_stored,
            'result': safe_label,
            'safe': bool(result),
            'protocols': protocols,
            'total_packets': total_packets,
            'elapsed_time': elapsed_time,
            'created_at': datetime.now(timezone.utc),
        }
        try:
            ins = mongo.db.detection_records.insert_one(detection_doc)
        except Exception as e:
            print(f"检测记录写入 MongoDB 失败: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'error': '检测已完成，但写入数据库失败，请检查 MongoDB 服务与连接配置',
                'detail': str(e),
            }), 500

        return jsonify({
            'message': '检测完成',
            'result': safe_label,
            'elapsed_time': elapsed_time,
            'total_packets': total_packets,
            'protocols': protocols,
            'file_size': os.path.getsize(pcap_save_path),
            'record_id': str(ins.inserted_id),
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/detection-history', methods=['GET'])
def detection_history():
    denied = _require_login_active()
    if denied:
        return denied

    username = session.get('username')
    cursor = (
        mongo.db.detection_records.find({'username': username})
        .sort('created_at', -1)
    )

    items = []
    safe_n = 0
    danger_n = 0
    protocols_total = {k: 0 for k in PROTOCOL_KEYS}
    total_elapsed = 0.0
    total_packets_sum = 0

    for doc in cursor:
        if doc.get('safe'):
            safe_n += 1
        else:
            danger_n += 1
        pr = doc.get('protocols') or {}
        for k in PROTOCOL_KEYS:
            protocols_total[k] += int(pr.get(k, 0) or 0)
        total_elapsed += float(doc.get('elapsed_time') or 0)
        total_packets_sum += int(doc.get('total_packets') or 0)
        items.append(_serialize_detection_doc(doc))

    total = safe_n + danger_n
    summary = {
        'total': total,
        'safe': safe_n,
        'danger': danger_n,
        'protocols_total': protocols_total,
        'avg_elapsed': round(total_elapsed / total, 2) if total else 0,
        'total_packets_sum': total_packets_sum,
    }

    return jsonify({'items': items, 'summary': summary}), 200


## ===================抓包协议分析 API（Web）====================================


@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify(capture_service.status()), 200


@app.route('/api/capture/interfaces', methods=['GET'])
def capture_interfaces():
    denied = _require_admin()
    if denied:
        return denied
    return jsonify({'interfaces': capture_service.list_interfaces()}), 200


@app.route('/api/capture/start', methods=['POST'])
def capture_start():
    denied = _require_admin()
    if denied:
        return denied
    if capture_service.status()['running']:
        return jsonify({'error': '已有进行中的抓包任务，请先停止'}), 400
    data = request.get_json(silent=True) or {}
    bpf = (data.get('bpf_filter') or '').strip()
    capture_service.start_live(bpf_filter=bpf)
    return jsonify({'message': '已开始实时抓包', 'status': capture_service.status()}), 200


@app.route('/api/capture/pause', methods=['POST'])
def capture_pause():
    denied = _require_admin()
    if denied:
        return denied
    capture_service.pause()
    return jsonify({'message': '已暂停', 'status': capture_service.status()}), 200


@app.route('/api/capture/resume', methods=['POST'])
def capture_resume():
    denied = _require_admin()
    if denied:
        return denied
    capture_service.resume()
    return jsonify({'message': '已继续', 'status': capture_service.status()}), 200


@app.route('/api/capture/stop', methods=['POST'])
def capture_stop():
    denied = _require_admin()
    if denied:
        return denied
    capture_service.stop()
    snap = capture_service.snapshot_for_db()
    session_doc = None
    if snap['packet_count'] > 0:
        fname = secure_filename(
            f"capture_{session.get('username', 'user')}_{int(time_module.time())}.pcap"
        )
        pcap_path = capture_service.save_pcap(app.config['UPLOAD_FOLDER'], fname)
        ended = datetime.now(timezone.utc)
        started = snap['meta'].get('started_at', ended)
        session_doc = {
            'username': session.get('username'),
            'user_id': session.get('user_id'),
            'mode': snap['mode'],
            'bpf_filter': snap['bpf_filter'],
            'status': 'stopped',
            'packet_count': snap['packet_count'],
            'pcap_filename': fname,
            'pcap_path': pcap_path,
            'source_file': snap['meta'].get('source_file'),
            'error': snap['meta'].get('error'),
            'started_at': started,
            'ended_at': ended,
            'annotation': None,
        }
        ins = mongo.db.capture_sessions.insert_one(session_doc)
        session_doc['id'] = str(ins.inserted_id)
    return jsonify({
        'message': '已停止抓包',
        'status': capture_service.status(),
        'session': session_doc,
    }), 200


@app.route('/api/capture/clear', methods=['POST'])
def capture_clear():
    denied = _require_admin()
    if denied:
        return denied
    capture_service.clear()
    return jsonify({'message': '已清空缓冲区', 'status': capture_service.status()}), 200


@app.route('/api/capture/open-pcap', methods=['POST'])
def capture_open_pcap():
    denied = _require_admin()
    if denied:
        return denied
    if capture_service.status()['running']:
        return jsonify({'error': '请先停止当前任务'}), 400
    f = request.files.get('file')
    if not f:
        return jsonify({'error': '没有文件'}), 400
    fname = secure_filename(f.filename)
    if not fname.lower().endswith('.pcap'):
        return jsonify({'error': '请上传 .pcap 文件'}), 400
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], f'offline_{fname}')
    f.save(save_path)
    bpf = (request.form.get('bpf_filter') or '').strip()
    capture_service.load_offline(save_path, bpf_filter=bpf)
    return jsonify({
        'message': '正在解析 pcap',
        'status': capture_service.status(),
    }), 200


@app.route('/api/capture/packet/<int:index>', methods=['GET'])
def capture_packet_detail(index):
    denied = _require_admin()
    if denied:
        return denied
    detail = capture_service.get_packet_detail(index)
    if detail is None:
        return jsonify({'error': '数据包不存在'}), 404
    return jsonify(detail), 200


@app.route('/api/capture/sessions', methods=['GET'])
def capture_sessions_list():
    denied = _require_admin()
    if denied:
        return denied
    cursor = (
        mongo.db.capture_sessions.find({'username': session.get('username')})
        .sort('ended_at', -1)
        .limit(20)
    )
    items = []
    for doc in cursor:
        items.append({
            'id': str(doc['_id']),
            'mode': doc.get('mode'),
            'packet_count': doc.get('packet_count', 0),
            'bpf_filter': doc.get('bpf_filter', ''),
            'pcap_filename': doc.get('pcap_filename'),
            'started_at': doc['started_at'].isoformat() if doc.get('started_at') else None,
            'ended_at': doc['ended_at'].isoformat() if doc.get('ended_at') else None,
            'annotation': doc.get('annotation'),
        })
    return jsonify({'items': items}), 200


@app.route('/api/capture/pending', methods=['GET'])
def capture_pending():
    """拉取自上次请求以来新到的包摘要（供前端轮询，避免 Vite 对 SSE 缓冲导致不刷新）。"""
    denied = _require_admin()
    if denied:
        return denied
    packets = capture_service.drain_pending()
    return jsonify({
        'packets': packets,
        'status': capture_service.status(),
    }), 200


@app.route('/api/capture/stream')
def capture_stream():
    denied = _require_admin()
    if denied:
        return denied

    def generate():
        while True:
            for pkt in capture_service.drain_pending():
                payload = {'type': 'packet', 'packet': pkt}
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            st = capture_service.status()
            hb = {'type': 'heartbeat', 'status': st}
            yield f"data: {json.dumps(hb, ensure_ascii=False)}\n\n"
            time_module.sleep(0.35)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@app.route('/api/capture/features-preview', methods=['POST'])
def capture_features_preview():
    """对当前缓冲区或指定已保存会话的 pcap 提取与模型一致的特征，并给出逐流预测。"""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    pcap_path = None
    temp_path = None
    try:
        if session_id:
            try:
                oid = ObjectId(str(session_id))
            except InvalidId:
                return jsonify({'error': '无效的会话 ID'}), 400
            doc = mongo.db.capture_sessions.find_one({
                '_id': oid,
                'username': session.get('username'),
            })
            if not doc:
                return jsonify({'error': '会话不存在'}), 404
            pcap_path = doc.get('pcap_path')
            if not pcap_path or not os.path.isfile(pcap_path):
                return jsonify({'error': '该会话没有可用的 pcap 文件'}), 400
        else:
            temp_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                f"preview_buf_{session.get('user_id', 'u')}_{int(time_module.time())}.pcap",
            )
            if not capture_service.dump_buffer_to_path(temp_path):
                return jsonify({'error': '缓冲区内没有数据包，请先抓包或指定 session_id'}), 400
            pcap_path = temp_path

        gf = GetFeature()
        feats = gf.MakeFeatures(pcap_path)
        if not feats:
            return jsonify({
                'columns': CAPTURE_FEATURE_COLUMNS,
                'flow_count': 0,
                'flows': [],
                'prediction_summary': '无流级特征（包太少或未形成连接）',
            }), 200

        x = np.array(feats, dtype=float)
        pred_arr = predicts(x)
        if hasattr(pred_arr, 'tolist'):
            pred_list = pred_arr.tolist()
        else:
            pred_list = list(pred_arr)

        safe_n = sum(1 for p in pred_list if int(p) == 1)
        flows_out = []
        for i, row in enumerate(feats):
            pi = int(pred_list[i]) if i < len(pred_list) else None
            flows_out.append({
                'index': i + 1,
                'features': [float(v) for v in row],
                'prediction': pi,
                'prediction_label': '安全' if pi == 1 else ('危险' if pi == 0 else '—'),
            })

        return jsonify({
            'columns': CAPTURE_FEATURE_COLUMNS,
            'flow_count': len(feats),
            'flows': flows_out[:80],
            'truncated': len(feats) > 80,
            'prediction_summary': f'共 {len(feats)} 条流，其中 {safe_n} 条判为安全，{len(feats) - safe_n} 条判为危险',
        }), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        if temp_path and os.path.isfile(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@app.route('/api/capture/sessions/<session_id>/annotate', methods=['POST'])
def capture_session_annotate(session_id):
    denied = _require_admin()
    if denied:
        return denied
    try:
        oid = ObjectId(str(session_id))
    except InvalidId:
        return jsonify({'error': '无效的会话 ID'}), 400
    data = request.get_json(silent=True) or {}
    ann = data.get('annotation')
    if ann in ('', None):
        set_val = None
    elif ann in ('normal', 'malicious'):
        set_val = ann
    else:
        return jsonify({'error': 'annotation 须为 normal、malicious 或空（清除）'}), 400

    res = mongo.db.capture_sessions.update_one(
        {'_id': oid, 'username': session.get('username')},
        {'$set': {'annotation': set_val}},
    )
    if res.matched_count == 0:
        return jsonify({'error': '会话不存在'}), 404
    return jsonify({'message': '已更新标注', 'annotation': set_val}), 200


@app.route('/api/train/rebuild', methods=['POST'])
def train_rebuild():
    """在默认 goodx/badx 上合并当前用户已标注会话的 pcap 特征后重新训练，并写入 model_runs。"""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    use_labeled = data.get('include_labeled_captures', True)
    username = session.get('username')

    good_paths = []
    bad_paths = []
    if use_labeled:
        for doc in mongo.db.capture_sessions.find({'username': username, 'annotation': 'normal'}):
            p = doc.get('pcap_path')
            if p and os.path.isfile(p):
                good_paths.append(p)
        for doc in mongo.db.capture_sessions.find({'username': username, 'annotation': 'malicious'}):
            p = doc.get('pcap_path')
            if p and os.path.isfile(p):
                bad_paths.append(p)

    try:
        warnings.filterwarnings('ignore')
        if use_labeled and (good_paths or bad_paths):
            metrics = run_with_extra_pcaps(
                extra_good_pcaps=good_paths or None,
                extra_bad_pcaps=bad_paths or None,
            )
        else:
            metrics = run()
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

    insert_doc = {
        'username': username,
        'created_at': datetime.now(timezone.utc),
        'train_score': metrics.get('train_score'),
        'test_score': metrics.get('test_score'),
        'extra_good_pcaps': len(good_paths),
        'extra_bad_pcaps': len(bad_paths),
        'include_labeled_captures': use_labeled,
    }
    ins = mongo.db.model_runs.insert_one(insert_doc)
    run_id = str(ins.inserted_id)
    rel_snapshot = _archive_model_snapshot_for_run(run_id)
    if rel_snapshot:
        mongo.db.model_runs.update_one({'_id': ins.inserted_id}, {'$set': {'model_file': rel_snapshot}})
    return jsonify({
        'message': '训练完成并已保存 model.pkl',
        'metrics': metrics,
        'merged_good_pcaps': len(good_paths),
        'merged_bad_pcaps': len(bad_paths),
        'run_id': run_id,
        'model_snapshot': rel_snapshot,
    }), 200


@app.route('/api/train/runs', methods=['GET'])
def train_runs_list():
    denied = _require_admin()
    if denied:
        return denied
    cursor = (
        mongo.db.model_runs.find({'username': session.get('username')})
        .sort('created_at', -1)
        .limit(15)
    )
    items = []
    for doc in cursor:
        rel = doc.get('model_file')
        can_restore = bool(rel and _resolved_model_archive_file(rel))
        items.append({
            'id': str(doc['_id']),
            'train_score': doc.get('train_score'),
            'test_score': doc.get('test_score'),
            'extra_good_pcaps': doc.get('extra_good_pcaps', 0),
            'extra_bad_pcaps': doc.get('extra_bad_pcaps', 0),
            'created_at': doc['created_at'].isoformat() if doc.get('created_at') else None,
            'can_restore': can_restore,
        })
    return jsonify({'items': items}), 200


@app.route('/api/train/restore', methods=['POST'])
def train_restore():
    """将某次训练归档的 model 快照复制回 train_test/model.pkl。"""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    run_id = data.get('run_id')
    if not run_id:
        return jsonify({'error': '缺少 run_id'}), 400
    try:
        oid = ObjectId(str(run_id))
    except InvalidId:
        return jsonify({'error': '无效的 run_id'}), 400
    username = session.get('username')
    doc = mongo.db.model_runs.find_one({'_id': oid, 'username': username})
    if not doc:
        return jsonify({'error': '记录不存在'}), 404
    rel = doc.get('model_file')
    if not rel:
        return jsonify({'error': '该条记录无模型快照（仅在本功能上线后的训练可恢复）'}), 400
    src = _resolved_model_archive_file(rel)
    if not src:
        return jsonify({'error': '快照文件不存在或已损坏'}), 404
    dst = _model_pkl_path()
    shutil.copy2(src, dst)
    mongo.db.model_runs.update_one(
        {'_id': oid},
        {'$set': {'restored_at': datetime.now(timezone.utc)}},
    )
    return jsonify({'message': '已将该版本恢复到当前使用的 model.pkl', 'run_id': str(oid)}), 200


## ===================管理员：用户管理 API====================================


@app.route('/api/admin/users', methods=['GET'])
def admin_users_list():
    denied = _require_admin()
    if denied:
        return denied
    q = (request.args.get('q') or '').strip()
    try:
        limit = min(max(int(request.args.get('limit', 30)), 1), 100)
        skip = max(int(request.args.get('skip', 0)), 0)
    except ValueError:
        return jsonify({'error': '无效的分页参数'}), 400

    filt = {}
    if q:
        filt['username'] = {'$regex': q, '$options': 'i'}

    total = mongo.db.users.count_documents(filt)
    cursor = (
        mongo.db.users.find(filt, {'password': 0})
        .sort('username', 1)
        .skip(skip)
        .limit(limit)
    )
    items = []
    for u in cursor:
        un = u.get('username') or ''
        det_total = mongo.db.detection_records.count_documents({'username': un})
        try:
            distinct_files = len(
                mongo.db.detection_records.distinct('filename', {'username': un})
            )
        except Exception:
            distinct_files = 0
        items.append({
            'id': str(u['_id']),
            'username': un,
            'role': u.get('role', 'user'),
            'status': u.get('status', USER_STATUS_ACTIVE),
            'detection_submit_count': det_total,
            'detection_distinct_pcap': distinct_files,
        })
    return jsonify({'items': items, 'total': total}), 200


@app.route('/api/admin/users/<user_id>', methods=['PATCH'])
def admin_user_patch(user_id):
    denied = _require_admin()
    if denied:
        return denied
    try:
        oid = ObjectId(str(user_id))
    except InvalidId:
        return jsonify({'error': '无效的用户 ID'}), 400

    data = request.get_json(silent=True) or {}
    updates = {}

    if 'password' in data and data['password']:
        pw = data['password']
        if len(pw) < 6 or len(pw) > 16:
            return jsonify({'error': '密码长度应为 6-16 个字符'}), 400
        updates['password'] = generate_password_hash(pw)

    if 'status' in data:
        st = data['status']
        if st not in (USER_STATUS_ACTIVE, USER_STATUS_BLOCKED):
            return jsonify({'error': 'status 须为 active 或 blocked'}), 400
        if st == USER_STATUS_BLOCKED and str(oid) == session.get('user_id'):
            return jsonify({'error': '不能封禁当前登录的管理员账号'}), 400
        updates['status'] = st

    if not updates:
        return jsonify({'error': '请提供 password 或 status'}), 400

    res = mongo.db.users.update_one({'_id': oid}, {'$set': updates})
    if res.matched_count == 0:
        return jsonify({'error': '用户不存在'}), 404
    return jsonify({'message': '已更新'}), 200


@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({'status': 'ok'}), 200
