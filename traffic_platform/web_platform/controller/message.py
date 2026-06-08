import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from flask import request, jsonify, session, Response, stream_with_context
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from traffic_platform.train_test.main import (
    analysis,
    analyze_pcap,
    DEFAULT_MALICIOUS_PROB_THRESHOLD,
    DEFAULT_MALICIOUS_RATIO_THRESHOLD,
    THRESHOLD_RULE_TEXT,
    evaluate_flows_decision,
    predicts,
    predicts_malicious_proba,
)
from traffic_platform.web_platform import app, mongo
from traffic_platform.web_platform.capture_service import capture_service
from traffic_platform.web_platform.audit_log import log_operation

import hashlib
import json
import shutil
import time as time_module
import warnings

import numpy as np
from bson import ObjectId
from bson.errors import InvalidId

from traffic_platform.train_test.get_feature import GetFeature
from traffic_platform.train_test.main import (
    MODEL_ALGORITHM_LABEL,
    MODEL_ALGORITHM_NAME,
    compute_baseline_metrics,
    read_deployed_model_info,
    run,
    run_with_extra_pcaps,
)
from traffic_platform.train_test.feature_schema import FEATURE_NAMES, feature_schema_payload

PROTOCOL_KEYS = ('TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'Other')
ALLOWED_PROTOCOL_TAGS = ('TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'DNS', 'TLS', 'OTHER')


def _normalize_protocol_tags(tags):
    if not tags:
        return []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.replace('，', ',').split(',') if t.strip()]
    out = []
    for t in tags:
        key = str(t).strip().upper()
        if key in ALLOWED_PROTOCOL_TAGS and key not in out:
            out.append(key)
    return out


def _protocol_tags_from_bpf(bpf_filter):
    expr = (bpf_filter or '').lower()
    if not expr:
        return []
    found = []
    mapping = (
        ('tcp port 80', 'HTTP'),
        ('udp', 'UDP'),
        ('tcp', 'TCP'),
        ('icmp', 'ICMP'),
        ('arp', 'ARP'),
        ('dns', 'DNS'),
        ('tls', 'TLS'),
    )
    for token, tag in mapping:
        if token in expr and tag not in found:
            found.append(tag)
    return found


def _protocol_tags_from_capture_summaries():
    """根据当前缓冲区内包摘要推断主要协议标签。"""
    try:
        summaries = capture_service.list_summaries()
    except Exception:
        return []
    tags = []
    for item in summaries[:800]:
        proto = str(item.get('proto') or '').upper()
        if proto == 'IP':
            continue
        if proto in ALLOWED_PROTOCOL_TAGS and proto not in tags:
            tags.append(proto)
        info = str(item.get('info') or '').upper()
        if 'DNS' in info and 'DNS' not in tags:
            tags.append('DNS')
        if 'TLS' in info and 'TLS' not in tags:
            tags.append('TLS')
        if ('PORT 80' in info or ':80' in info) and 'HTTP' not in tags:
            tags.append('HTTP')
    return tags[:6]


def _resolve_session_protocol_tags(bpf_filter):
    tags = _protocol_tags_from_bpf(bpf_filter)
    if tags:
        return tags
    return _protocol_tags_from_capture_summaries()


def _resolve_training_selected(doc):
    """是否在训练样本池中：已标注且未显式移出（training_pool_opt_out）。"""
    if doc.get('training_pool_opt_out'):
        return False
    return doc.get('annotation') in ('normal', 'malicious')


def _training_pool_query(username):
    """返回训练样本池查询条件（已标注且未显式移出）。"""
    return {
        'username': username,
        'annotation': {'$in': ['normal', 'malicious']},
        'training_pool_opt_out': {'$ne': True},
    }


def _collect_training_pool_sessions(username):
    cursor = mongo.db.capture_sessions.find(_training_pool_query(username))
    good_paths = []
    bad_paths = []
    used_docs = []
    for doc in cursor:
        p = doc.get('pcap_path')
        if not p or not os.path.isfile(p):
            continue
        used_docs.append(doc)
        if doc.get('annotation') == 'normal':
            good_paths.append(p)
        elif doc.get('annotation') == 'malicious':
            bad_paths.append(p)
    return good_paths, bad_paths, used_docs


def _snapshot_merged_session(doc):
    """训练时快照标注会话，供评估页展示本次合并了哪些 pcap。"""
    pcap_path = doc.get('pcap_path')
    flow_count = 0
    if pcap_path and os.path.isfile(pcap_path):
        try:
            flow_count = len(GetFeature().MakeFeatures(pcap_path))
        except Exception:
            flow_count = 0
    session_mode = _resolve_capture_session_mode(doc)
    fname = (
        doc.get('source_file')
        if session_mode == 'offline' and doc.get('source_file')
        else doc.get('pcap_filename')
    )
    annotation = doc.get('annotation')
    return {
        'session_id': str(doc['_id']),
        'filename': fname or '—',
        'annotation': annotation,
        'annotation_label': {
            'normal': '正常样本',
            'malicious': '恶意样本',
        }.get(annotation, '—'),
        'packet_count': doc.get('packet_count', 0),
        'flow_count': flow_count,
        'protocol_tags': doc.get('protocol_tags') or [],
        'mode': session_mode,
        'mode_label': '离线' if session_mode == 'offline' else '实时',
    }


def _infer_merged_sessions_for_legacy_run(doc, username):
    """旧版训练记录未写入 merged_session_ids 时，按份数与时间推断可能纳入的会话。"""
    if not username:
        return []
    extra_normal = int(doc.get('extra_good_pcaps') or 0)
    extra_bad = int(doc.get('extra_bad_pcaps') or 0)
    need_total = extra_normal + extra_bad
    if need_total <= 0:
        return []
    run_at = doc.get('created_at')
    q = {
        'username': username,
        'annotation': {'$in': ['normal', 'malicious']},
    }
    if run_at:
        q['ended_at'] = {'$lte': run_at}
    cursor = mongo.db.capture_sessions.find(q).sort('ended_at', -1)
    normals, mals = [], []
    for sdoc in cursor:
        p = sdoc.get('pcap_path')
        if not p or not os.path.isfile(p):
            continue
        ann = sdoc.get('annotation')
        if ann == 'normal' and len(normals) < extra_normal:
            normals.append(sdoc)
        elif ann == 'malicious' and len(mals) < extra_bad:
            mals.append(sdoc)
        if len(normals) >= extra_normal and len(mals) >= extra_bad:
            break
    picked = normals + mals
    if len(picked) != need_total:
        return []
    return [_snapshot_merged_session(d) for d in picked]


def _merged_sessions_for_run_doc(doc, username=None):
    """返回某次训练纳入的标注会话明细（优先训练时快照，旧记录按 id / 关联字段回查）。"""
    stored = doc.get('merged_sessions')
    if stored:
        return stored

    ids = doc.get('merged_session_ids') or []
    if ids:
        merged = []
        for sid in ids:
            try:
                oid = ObjectId(sid)
            except InvalidId:
                continue
            sdoc = mongo.db.capture_sessions.find_one({'_id': oid})
            if sdoc:
                merged.append(_snapshot_merged_session(sdoc))
            else:
                merged.append({
                    'session_id': sid,
                    'filename': '（会话已删除）',
                    'annotation': None,
                    'annotation_label': '—',
                    'packet_count': 0,
                    'flow_count': 0,
                    'protocol_tags': [],
                    'mode': None,
                    'mode_label': '—',
                })
        if merged:
            return merged

    run_id = str(doc.get('_id', ''))
    if run_id:
        trained = list(mongo.db.capture_sessions.find({'trained_run_id': run_id}))
        if trained:
            return [_snapshot_merged_session(d) for d in trained]

    return _infer_merged_sessions_for_legacy_run(doc, username)


def _resolve_capture_session_mode(doc):
    """离线=用户上传的 pcap；实时=网卡抓包。以 source_file / capture_origin 为准。"""
    if doc.get('source_file'):
        return 'offline'
    origin = doc.get('capture_origin') or doc.get('mode')
    if origin == 'offline':
        return 'offline' if doc.get('source_file') else 'live'
    return 'live'


def _utc_iso(dt):
    """将 datetime 序列化为带 Z 的 UTC ISO 字符串，避免前端按本地时区误解析。"""
    if not dt:
        return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    text = dt.strftime('%Y-%m-%dT%H:%M:%S')
    if dt.microsecond:
        text += f'.{dt.microsecond:06d}'.rstrip('0').rstrip('.')
    return text + 'Z'


def _parse_threshold(value, default, name='threshold'):
    if value is None or value == '':
        return default
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{name} 须为 0～1 之间的数字')
    if v < 0 or v > 1:
        raise ValueError(f'{name} 须在 0～1 之间')
    return v


def _preview_summary_text(decision):
    n = decision.get('flow_count', 0)
    if n == 0:
        return '无流级特征（包太少或未形成连接）'
    safe_n = n - decision.get('malicious_flow_count', 0)
    file_label = '安全' if decision.get('is_safe') else '危险'
    triggers = []
    if decision.get('triggered_by_prob'):
        triggers.append('存在高概率恶意流')
    if decision.get('triggered_by_ratio'):
        triggers.append('恶意流占比超阈')
    trigger_txt = f'（触发：{"、".join(triggers)}）' if triggers else ''
    return (
        f'共 {n} 条流，硬分类 {safe_n} 安全 / {decision.get("malicious_flow_count", 0)} 危险；'
        f'最高恶意概率 {decision.get("max_malicious_prob", 0) * 100:.1f}%；'
        f'文件级（阈值策略）判为 {file_label}{trigger_txt}'
    )


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


def _file_fingerprint(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def _model_algorithm_from_run_doc(doc):
    algo = (
        doc.get('model_algorithm')
        or doc.get('selected_algorithm')
        or doc.get('primary_algorithm')
    )
    if not algo:
        return MODEL_ALGORITHM_NAME, MODEL_ALGORITHM_LABEL
    algo = str(algo)
    if algo == 'RandomForest':
        return algo, MODEL_ALGORITHM_LABEL
    return algo, algo


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

CAPTURE_FEATURE_COLUMNS = list(FEATURE_NAMES)


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
        log_operation(
            mongo, 'login_fail', username=username, success=False, detail='用户名不存在',
        )
        return jsonify({'error': '用户名不存在'}), 401
    elif not check_password_hash(user['password'], password):
        log_operation(
            mongo, 'login_fail', username=username, success=False, detail='密码错误',
        )
        return jsonify({'error': '密码错误'}), 401
    elif user.get('status', USER_STATUS_ACTIVE) == USER_STATUS_BLOCKED:
        log_operation(
            mongo, 'login_fail', username=username, success=False, detail='账号已封禁',
        )
        return jsonify({'error': '账号已被封禁，请联系管理员'}), 403
    else:
        session['logged_in'] = True
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['role'] = user.get('role', 'user')
        log_operation(
            mongo, 'login_success', username=user['username'], user_id=str(user['_id']),
            detail=f"role={user.get('role', 'user')}",
        )
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
    ins = mongo.db.users.insert_one({
        'username': username,
        'password': hashed_password,
        'role': user_role,
        'status': USER_STATUS_ACTIVE,
    })
    log_operation(
        mongo, 'register', username=username, user_id=str(ins.inserted_id),
        target_type='user', target_id=str(ins.inserted_id), detail=f'role={user_role}',
    )

    return jsonify({'message': '注册成功', 'role': user_role}), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    log_operation(mongo, 'logout')
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return jsonify({'message': '已退出登录'}), 200


@app.route('/api/check-session', methods=['GET']) # 检查登录状态
def check_session():
    if not session.get('logged_in'): # 检查会话状态
        return jsonify({'logged_in': False}), 200
    user = _user_doc_by_session()
    if not user or user.get('status', USER_STATUS_ACTIVE) == USER_STATUS_BLOCKED:# 判断用户状态是否被阻塞
        session.clear()
        return jsonify({'logged_in': False}), 200
    return jsonify({ # 返回用户信息 （json格式）mongodb表中定义
        'logged_in': True,
        'username': user.get('username'),
        'role': user.get('role', 'user'),
        'status': user.get('status', USER_STATUS_ACTIVE),
        'user_id': str(user['_id']),
    }), 200


@app.route('/api/profile/change-password', methods=['POST'])
def profile_change_password():
    """当前登录用户修改自己的密码（需校验原密码）。"""
    denied = _require_login_active()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    if not old_password or not new_password:
        return jsonify({'error': '请填写原密码和新密码'}), 400
    if len(new_password) < 6 or len(new_password) > 16:
        return jsonify({'error': '新密码长度应为 6-16 个字符'}), 400
    if new_password != confirm_password:
        return jsonify({'error': '两次输入的新密码不一致'}), 400
    if old_password == new_password:
        return jsonify({'error': '新密码不能与原密码相同'}), 400

    user = _user_doc_by_session()
    if not user:
        return jsonify({'error': '请重新登录'}), 401
    if not check_password_hash(user['password'], old_password):
        log_operation(
            mongo, 'change_password', success=False, detail='原密码错误',
        )
        return jsonify({'error': '原密码错误'}), 400

    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'password': generate_password_hash(new_password)}},
    )
    log_operation(mongo, 'change_password', detail='密码已更新')
    return jsonify({'message': '密码修改成功，请使用新密码登录'}), 200


## ===================文件检测 API====================================

@app.route('/api/detection/thresholds', methods=['GET'])
def detection_thresholds():
    """返回文件级恶意判定默认阈值及规则说明。"""
    denied = _require_login_active()
    if denied:
        return denied
    return jsonify({
        'prob_threshold': DEFAULT_MALICIOUS_PROB_THRESHOLD,
        'ratio_threshold': DEFAULT_MALICIOUS_RATIO_THRESHOLD,
        'rule_text': THRESHOLD_RULE_TEXT,
        'prob_threshold_hint': '单条流恶意概率 ≥ 该值时，文件可判为危险',
        'ratio_threshold_hint': '硬分类为恶意的流占比 > 该值时，文件可判为危险',
    }), 200


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
        
        try:
            prob_th = _parse_threshold(
                request.form.get('prob_threshold'),
                DEFAULT_MALICIOUS_PROB_THRESHOLD,
                'prob_threshold',
            )
            ratio_th = _parse_threshold(
                request.form.get('ratio_threshold'),
                DEFAULT_MALICIOUS_RATIO_THRESHOLD,
                'ratio_threshold',
            )
        except ValueError as ve:
            return jsonify({'error': str(ve)}), 400

        flow_eval = analyze_pcap(pcap_save_path, prob_th, ratio_th)
        result = bool(flow_eval.get('is_safe', True))
        
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
            'flow_count': flow_eval.get('flow_count', 0),
            'malicious_flow_count': flow_eval.get('malicious_flow_count', 0),
            'malicious_flow_ratio': flow_eval.get('malicious_flow_ratio', 0),
            'max_malicious_prob': flow_eval.get('max_malicious_prob', 0),
            'prob_threshold': flow_eval.get('prob_threshold'),
            'ratio_threshold': flow_eval.get('ratio_threshold'),
            'triggered_by_prob': flow_eval.get('triggered_by_prob', False),
            'triggered_by_ratio': flow_eval.get('triggered_by_ratio', False),
            'created_at': datetime.now(timezone.utc),
        }
        try:
            ins = mongo.db.detection_records.insert_one(detection_doc)
            log_operation(
                mongo, 'detection',
                target_type='detection_record',
                target_id=str(ins.inserted_id),
                detail=f'{filename_stored} → {safe_label}',
            )
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
            'safe': bool(result),
            'elapsed_time': elapsed_time,
            'total_packets': total_packets,
            'protocols': protocols,
            'file_size': os.path.getsize(pcap_save_path),
            'record_id': str(ins.inserted_id),
            'flow_analysis': {
                'flow_count': flow_eval.get('flow_count', 0),
                'malicious_flow_count': flow_eval.get('malicious_flow_count', 0),
                'malicious_flow_ratio': flow_eval.get('malicious_flow_ratio', 0),
                'high_prob_flow_count': flow_eval.get('high_prob_flow_count', 0),
                'max_malicious_prob': flow_eval.get('max_malicious_prob', 0),
                'prob_threshold': flow_eval.get('prob_threshold'),
                'ratio_threshold': flow_eval.get('ratio_threshold'),
                'triggered_by_prob': flow_eval.get('triggered_by_prob', False),
                'triggered_by_ratio': flow_eval.get('triggered_by_ratio', False),
                'rule_text': flow_eval.get('rule_text', THRESHOLD_RULE_TEXT),
            },
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
    try:
        capture_service.start_live(bpf_filter=bpf)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
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
    was_running = capture_service.status().get('running')
    capture_service.stop()
    snap = capture_service.snapshot_for_db()
    session_doc = None
    if snap['packet_count'] > 0:
        meta = snap.get('meta') or {}
        session_mode = snap.get('capture_origin')
        if session_mode not in ('live', 'offline'):
            session_mode = meta.get('session_mode')
        if session_mode not in ('live', 'offline'):
            session_mode = 'offline' if meta.get('source_file') else 'live'
        fname = secure_filename(
            f"capture_{session.get('username', 'user')}_{int(time_module.time())}.pcap"
        )
        pcap_path = capture_service.save_pcap(app.config['UPLOAD_FOLDER'], fname)
        started = meta.get('started_at') or datetime.now(timezone.utc)
        if session_mode == 'offline':
            ended = meta.get('opened_at') or meta.get('started_at') or datetime.now(timezone.utc)
        else:
            ended = datetime.now(timezone.utc)
        session_doc = {
            'username': session.get('username'),
            'user_id': session.get('user_id'),
            'mode': session_mode,
            'capture_origin': session_mode,
            'bpf_filter': snap['bpf_filter'],
            'status': 'stopped',
            'packet_count': snap['packet_count'],
            'pcap_filename': fname,
            'pcap_path': pcap_path,
            'source_file': meta.get('source_file') if session_mode == 'offline' else None,
            'error': meta.get('error'),
            'started_at': started,
            'ended_at': ended,
            'annotation': None,
            'protocol_tags': _resolve_session_protocol_tags(snap['bpf_filter']),
        }
        ins = mongo.db.capture_sessions.insert_one(session_doc)
        session_doc['id'] = str(ins.inserted_id)
        log_operation(
            mongo, 'capture_stop',
            target_type='capture_session',
            target_id=str(ins.inserted_id),
            detail=f'{fname}，{snap["packet_count"]} 包',
        )
    msg = '已停止抓包'
    if session_doc and not was_running:
        msg = '离线会话已保存'
    elif session_doc:
        msg = '已停止抓包并保存会话'
    elif snap['packet_count'] == 0:
        msg = '无数据包可保存'
    return jsonify({
        'message': msg,
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
    lower = fname.lower()
    if not (lower.endswith('.pcap') or lower.endswith('.pcapng')):
        return jsonify({'error': '请上传 .pcap / .pcapng 文件'}), 400
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], f'offline_{fname}')
    f.save(save_path)
    opened_at = datetime.now(timezone.utc)
    capture_service.load_offline(save_path, bpf_filter='', opened_at=opened_at)
    return jsonify({
        'message': '正在解析 pcap（未应用 BPF，可填写后点「查询」）',
        'status': capture_service.status(),
    }), 200


@app.route('/api/capture/apply-bpf', methods=['POST'])
def capture_apply_bpf():
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    bpf = (data.get('bpf_filter') or '').strip()
    if not bpf:
        return jsonify({'error': '请填写 BPF 过滤表达式'}), 400
    try:
        capture_service.apply_bpf(bpf_filter=bpf)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 400
    except FileNotFoundError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({
        'message': '正在按 BPF 重新过滤',
        'status': capture_service.status(),
    }), 200


@app.route('/api/capture/cancel-bpf', methods=['POST'])
def capture_cancel_bpf():
    denied = _require_admin()
    if denied:
        return denied
    try:
        capture_service.cancel_bpf()
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 400
    except FileNotFoundError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({
        'message': '已取消 BPF，正在重新加载全部数据包',
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
        mode = _resolve_capture_session_mode(doc)
        items.append({
            'id': str(doc['_id']),
            'mode': mode,
            'packet_count': doc.get('packet_count', 0),
            'bpf_filter': doc.get('bpf_filter', ''),
            'pcap_filename': doc.get('pcap_filename'),
            'source_file': doc.get('source_file'),
            'started_at': _utc_iso(doc.get('started_at')),
            'ended_at': _utc_iso(doc.get('ended_at')),
            'annotation': doc.get('annotation'),
            'protocol_tags': doc.get('protocol_tags') or [],
            'training_selected': _resolve_training_selected(doc),
        })
    return jsonify({'items': items}), 200


@app.route('/api/capture/packets', methods=['GET'])
def capture_packets_list():
    """返回当前缓冲区全部包摘要（离线 pcap 解析很快结束时，避免前端轮询漏包）。"""
    denied = _require_admin()
    if denied:
        return denied
    packets = capture_service.list_summaries()
    st = capture_service.status()
    return jsonify({
        'packets': packets,
        'packet_count': st['packet_count'],
        'status': st,
    }), 200


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

        try:
            prob_th = _parse_threshold(
                data.get('prob_threshold'),
                DEFAULT_MALICIOUS_PROB_THRESHOLD,
                'prob_threshold',
            )
            ratio_th = _parse_threshold(
                data.get('ratio_threshold'),
                DEFAULT_MALICIOUS_RATIO_THRESHOLD,
                'ratio_threshold',
            )
        except ValueError as ve:
            return jsonify({'error': str(ve)}), 400

        x = np.array(feats, dtype=float)
        pred_arr = predicts(x)
        proba_arr = predicts_malicious_proba(x)
        decision = evaluate_flows_decision(pred_arr, proba_arr, prob_th, ratio_th)
        if hasattr(pred_arr, 'tolist'):
            pred_list = pred_arr.tolist()
        else:
            pred_list = list(pred_arr)

        flows_out = []
        for i, row in enumerate(feats):
            pi = int(pred_list[i]) if i < len(pred_list) else None
            mp = float(proba_arr[i]) if i < len(proba_arr) else None
            flows_out.append({
                'index': i + 1,
                'features': [float(v) for v in row],
                'prediction': pi,
                'prediction_label': '安全' if pi == 1 else ('危险' if pi == 0 else '—'),
                'malicious_prob': mp,
                'high_risk': bool(mp is not None and mp >= prob_th),
            })

        return jsonify({
            'columns': CAPTURE_FEATURE_COLUMNS,
            'flow_count': len(feats),
            'flows': flows_out[:80],
            'truncated': len(feats) > 80,
            'prediction_summary': _preview_summary_text(decision),
            'file_decision': {
                'is_safe': decision.get('is_safe', True),
                'label': '安全' if decision.get('is_safe') else '危险',
                **{k: decision.get(k) for k in (
                    'malicious_flow_count', 'malicious_flow_ratio', 'high_prob_flow_count',
                    'max_malicious_prob', 'prob_threshold', 'ratio_threshold',
                    'triggered_by_prob', 'triggered_by_ratio', 'rule_text',
                )},
            },
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
    protocol_tags = data.get('protocol_tags')
    set_fields = {}
    unset_fields = {}
    if 'annotation' in data:
        if isinstance(ann, str):
            ann = ann.strip()
        if ann in ('', None):
            unset_fields['annotation'] = ''
            unset_fields['training_selected'] = ''
            unset_fields['training_pool_opt_out'] = ''
            set_val = None
        elif ann in ('normal', 'malicious'):
            set_fields['annotation'] = ann
            set_fields['training_selected'] = True
            unset_fields['training_pool_opt_out'] = ''
            set_val = ann
        else:
            return jsonify({'error': 'annotation 须为 normal、malicious 或空（清除标注）'}), 400
    else:
        set_val = 'unchanged'

    if protocol_tags is not None:
        set_fields['protocol_tags'] = _normalize_protocol_tags(protocol_tags)

    if not set_fields and not unset_fields:
        return jsonify({'error': '请提供 annotation 或 protocol_tags'}), 400

    update_doc = {}
    if set_fields:
        update_doc['$set'] = set_fields
    if unset_fields:
        update_doc['$unset'] = unset_fields

    res = mongo.db.capture_sessions.update_one(
        {'_id': oid, 'username': session.get('username')},
        update_doc,
    )
    if res.matched_count == 0:
        return jsonify({'error': '会话不存在'}), 404

    doc = mongo.db.capture_sessions.find_one({'_id': oid})
    if set_val == 'unchanged':
        ann_detail = '更新协议标签'
    else:
        ann_detail = '清除标注' if set_val is None else f'标注为 {set_val}'
    if protocol_tags is not None and set_val != 'unchanged':
        ann_detail += f'；协议 {",".join(set_fields.get("protocol_tags", []))}'
    log_operation(
        mongo, 'annotate_session',
        target_type='capture_session',
        target_id=session_id,
        detail=ann_detail,
    )
    return jsonify({
        'message': '已更新会话',
        'annotation': doc.get('annotation'),
        'protocol_tags': doc.get('protocol_tags') or [],
        'training_selected': _resolve_training_selected(doc),
    }), 200


@app.route('/api/capture/sessions/<session_id>/training-pool', methods=['POST'])
def capture_session_training_pool(session_id):
    """将已标注会话加入或移出训练样本池。"""
    denied = _require_admin()
    if denied:
        return denied
    try:
        oid = ObjectId(str(session_id))
    except InvalidId:
        return jsonify({'error': '无效的会话 ID'}), 400
    data = request.get_json(silent=True) or {}
    if 'selected' not in data:
        return jsonify({'error': '请提供 selected（true/false）'}), 400
    selected = bool(data.get('selected'))

    doc = mongo.db.capture_sessions.find_one({
        '_id': oid,
        'username': session.get('username'),
    })
    if not doc:
        return jsonify({'error': '会话不存在'}), 404
    if doc.get('annotation') not in ('normal', 'malicious'):
        return jsonify({'error': '请先标注为正常或恶意样本，再加入训练池'}), 400

    update_doc = {'$set': {'training_selected': selected}}
    if selected:
        update_doc['$unset'] = {'training_pool_opt_out': ''}
    else:
        update_doc['$set']['training_pool_opt_out'] = True
    mongo.db.capture_sessions.update_one({'_id': oid}, update_doc)
    doc = mongo.db.capture_sessions.find_one({'_id': oid})
    action = '加入训练池' if selected else '移出训练池'
    log_operation(
        mongo, 'training_pool',
        target_type='capture_session',
        target_id=session_id,
        detail=action,
    )
    return jsonify({
        'message': f'已{action}',
        'training_selected': _resolve_training_selected(doc),
    }), 200


@app.route('/api/capture/sessions/<session_id>', methods=['DELETE'])
def capture_session_delete(session_id):
    """删除已保存会话及对应 pcap 文件。"""
    denied = _require_admin()
    if denied:
        return denied
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
    if pcap_path and os.path.isfile(pcap_path):
        try:
            os.remove(pcap_path)
        except OSError as exc:
            return jsonify({'error': f'删除 pcap 文件失败: {exc}'}), 500

    mongo.db.capture_sessions.delete_one({'_id': oid, 'username': session.get('username')})
    log_operation(
        mongo, 'delete_session',
        target_type='capture_session',
        target_id=session_id,
        detail=doc.get('pcap_filename') or session_id,
    )
    return jsonify({'message': '已删除会话'}), 200


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
    used_session_docs = []
    if use_labeled:
        good_paths, bad_paths, used_session_docs = _collect_training_pool_sessions(username)

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
        'malicious_recall': metrics.get('malicious_recall'),
        'malicious_f1': metrics.get('malicious_f1'),
        'confusion_matrix': metrics.get('confusion_matrix'),
        'feature_importance': metrics.get('feature_importance'),
        'feature_count': metrics.get('feature_count'),
        'sample_total': metrics.get('sample_total'),
        'sample_normal': metrics.get('sample_normal'),
        'sample_malicious': metrics.get('sample_malicious'),
        'train_set_size': metrics.get('train_set_size'),
        'train_set_normal': metrics.get('train_set_normal'),
        'train_set_malicious': metrics.get('train_set_malicious'),
        'test_set_size': metrics.get('test_set_size'),
        'test_set_normal': metrics.get('test_set_normal'),
        'test_set_malicious': metrics.get('test_set_malicious'),
        'extra_good_pcaps': metrics.get('extra_normal_pcaps', len(good_paths)),
        'extra_bad_pcaps': metrics.get('extra_malicious_pcaps', len(bad_paths)),
        'local_normal_flows': metrics.get('local_normal_flows'),
        'local_malicious_flows': metrics.get('local_malicious_flows'),
        'extra_normal_flows': metrics.get('extra_normal_flows'),
        'extra_malicious_flows': metrics.get('extra_malicious_flows'),
        'extra_normal_packets': metrics.get('extra_normal_packets'),
        'extra_malicious_packets': metrics.get('extra_malicious_packets'),
        'include_labeled_captures': use_labeled,
        'merged_session_ids': [str(d['_id']) for d in used_session_docs],
        'merged_sessions': [_snapshot_merged_session(d) for d in used_session_docs],
        'extra_good_pcaps_paths': list(good_paths),
        'extra_bad_pcaps_paths': list(bad_paths),
        'model_algorithm': metrics.get('model_algorithm', MODEL_ALGORITHM_NAME),
    }
    if metrics.get('baseline_comparison'):
        insert_doc['baseline_comparison'] = _finalize_baseline_for_run(
            metrics['baseline_comparison'],
            insert_doc,
            data_source='train_snapshot',
        )
    ins = mongo.db.model_runs.insert_one(insert_doc)
    run_id = str(ins.inserted_id)
    rel_snapshot = _archive_model_snapshot_for_run(run_id)
    if rel_snapshot:
        mongo.db.model_runs.update_one({'_id': ins.inserted_id}, {'$set': {'model_file': rel_snapshot}})
    log_operation(
        mongo, 'train_rebuild',
        target_type='model_run',
        target_id=run_id,
        detail=f'pool={len(used_session_docs)} good_pcap={len(good_paths)} bad_pcap={len(bad_paths)}',
    )
    pool_tip = f'训练池 {len(used_session_docs)} 个 pcap' if used_session_docs else '仅 goodx/badx'
    return jsonify({
        'message': f'训练完成（{pool_tip}），随机森林模型已写入 model.pkl',
        'metrics': metrics,
        'merged_good_pcaps': len(good_paths),
        'merged_bad_pcaps': len(bad_paths),
        'merged_session_count': len(used_session_docs),
        'run_id': run_id,
        'model_snapshot': rel_snapshot,
    }), 200


@app.route('/api/train/labeled-summary', methods=['GET'])
def train_labeled_summary():
    denied = _require_admin()
    if denied:
        return denied
    username = session.get('username')
    labeled_q = {'username': username, 'annotation': {'$in': ['normal', 'malicious']}}
    labeled = list(mongo.db.capture_sessions.find(labeled_q))
    pool = [d for d in labeled if _resolve_training_selected(d)]
    not_in_pool = [d for d in labeled if not _resolve_training_selected(d)]
    return jsonify({
        'pool': {
            'normal': sum(1 for d in pool if d.get('annotation') == 'normal'),
            'malicious': sum(1 for d in pool if d.get('annotation') == 'malicious'),
            'total': len(pool),
        },
        'labeled_not_in_pool': {
            'normal': sum(1 for d in not_in_pool if d.get('annotation') == 'normal'),
            'malicious': sum(1 for d in not_in_pool if d.get('annotation') == 'malicious'),
            'total': len(not_in_pool),
        },
    }), 200


@app.route('/api/train/feature-schema', methods=['GET'])
def train_feature_schema():
    """返回流级特征名称及网安含义（文档说明）。"""
    denied = _require_admin()
    if denied:
        return denied
    return jsonify(feature_schema_payload()), 200


def _pcap_paths_for_run_merged_sessions(doc, username):
    """按训练记录中保存的会话 ID 还原当时合并的 pcap 路径。"""
    good_paths, bad_paths = [], []
    if not doc.get('include_labeled_captures', True):
        return good_paths, bad_paths
    for sid in doc.get('merged_session_ids') or []:
        try:
            oid = ObjectId(sid)
        except InvalidId:
            continue
        sdoc = mongo.db.capture_sessions.find_one({'_id': oid, 'username': username})
        if not sdoc:
            continue
        p = sdoc.get('pcap_path')
        if not p or not os.path.isfile(p):
            continue
        if sdoc.get('annotation') == 'normal':
            good_paths.append(p)
        elif sdoc.get('annotation') == 'malicious':
            bad_paths.append(p)
    return good_paths, bad_paths


def _training_data_note_for_run(doc):
    """描述该次训练用于对比的样本范围。"""
    merged_n = len(doc.get('merged_session_ids') or [])
    use_labeled = doc.get('include_labeled_captures', True)
    parts = ['goodx/badx']
    if use_labeled and merged_n:
        parts.append(f'本次重训纳入的 {merged_n} 个标注 pcap')
    return ' + '.join(parts)


def _patch_baseline_primary_from_run(baseline, doc):
    """基线表中随机森林行与训练记录已保存指标对齐。"""
    if not baseline or not doc:
        return baseline
    models = baseline.get('models')
    if not models:
        return baseline
    patched = {**baseline, 'models': [dict(m) for m in models]}
    for m in patched['models']:
        if not m.get('is_primary'):
            continue
        if doc.get('train_score') is not None:
            m['train_score'] = float(doc['train_score'])
        if doc.get('test_score') is not None:
            m['test_score'] = float(doc['test_score'])
        if doc.get('malicious_recall') is not None:
            m['malicious_recall'] = float(doc['malicious_recall'])
        if doc.get('malicious_f1') is not None:
            m['malicious_f1'] = float(doc['malicious_f1'])
        break
    data_note = baseline.get('training_data_note') or _training_data_note_for_run(doc)
    patched['training_data_note'] = data_note
    patched['description'] = (
        f'对比数据与本次重训一致（{data_note}），三种算法同一 7:3 划分；'
        f'仅随机森林写入 model.pkl。上方指标卡片为随机森林实测结果。'
    )
    return patched


def _finalize_baseline_for_run(baseline, doc, data_source='train_snapshot'):
    """写入训练记录时固化基线对比的样本来源说明。"""
    if not baseline:
        return None
    out = {**baseline, 'data_source': data_source}
    out['training_data_note'] = _training_data_note_for_run(doc)
    return _patch_baseline_primary_from_run(out, doc)


def _training_data_paths_for_run(doc, username):
    """还原该次重训实际使用的标注 pcap 路径（不用当前训练池）。"""
    good, bad = [], []
    for p in doc.get('extra_good_pcaps_paths') or []:
        if p and os.path.isfile(p):
            good.append(p)
    for p in doc.get('extra_bad_pcaps_paths') or []:
        if p and os.path.isfile(p):
            bad.append(p)
    if good or bad:
        return good, bad
    if not doc.get('include_labeled_captures', True):
        return [], []
    return _pcap_paths_for_run_merged_sessions(doc, username)


def _ensure_run_baseline(doc, username):
    """按该次重训保存的样本重算基线；重训当场生成的基线则直接复用。"""
    existing = doc.get('baseline_comparison')
    if existing and existing.get('data_source') == 'train_snapshot':
        return _patch_baseline_primary_from_run(existing, doc)
    try:
        warnings.filterwarnings('ignore')
        good_paths, bad_paths = _training_data_paths_for_run(doc, username)
        use_labeled = doc.get('include_labeled_captures', True)
        if use_labeled and (good_paths or bad_paths):
            baseline = compute_baseline_metrics(
                extra_good_pcaps=good_paths or None,
                extra_bad_pcaps=bad_paths or None,
            )
        else:
            baseline = compute_baseline_metrics()
        baseline = _finalize_baseline_for_run(baseline, doc, data_source='run_merged_paths')
        mongo.db.model_runs.update_one(
            {'_id': doc['_id']},
            {'$set': {'baseline_comparison': baseline}},
        )
        return baseline
    except Exception:
        import traceback
        traceback.print_exc()
        return None


def _serialize_model_run_doc(doc, username, active_fp=None, ensure_baseline=False):
    rel = doc.get('model_file')
    snap_path = _resolved_model_archive_file(rel) if rel else None
    can_restore = bool(snap_path)
    is_active = bool(
        active_fp and snap_path and _file_fingerprint(snap_path) == active_fp
    )
    algo_name, algo_label = _model_algorithm_from_run_doc(doc)
    baseline = doc.get('baseline_comparison')
    if ensure_baseline:
        if not (baseline and baseline.get('data_source') == 'train_snapshot'):
            baseline = _ensure_run_baseline(doc, username)
        elif baseline:
            baseline = _patch_baseline_primary_from_run(baseline, doc)
    elif baseline and baseline.get('models'):
        baseline = _patch_baseline_primary_from_run(baseline, doc)
    return {
        'id': str(doc['_id']),
        'model_algorithm': algo_name,
        'model_algorithm_label': algo_label,
        'is_active': is_active,
        'train_score': doc.get('train_score'),
        'test_score': doc.get('test_score'),
        'malicious_recall': doc.get('malicious_recall'),
        'malicious_f1': doc.get('malicious_f1'),
        'confusion_matrix': doc.get('confusion_matrix'),
        'feature_importance': doc.get('feature_importance'),
        'baseline_comparison': baseline,
        'feature_count': doc.get('feature_count'),
        'sample_total': doc.get('sample_total'),
        'sample_normal': doc.get('sample_normal'),
        'sample_malicious': doc.get('sample_malicious'),
        'train_set_size': doc.get('train_set_size'),
        'train_set_normal': doc.get('train_set_normal'),
        'train_set_malicious': doc.get('train_set_malicious'),
        'test_set_size': doc.get('test_set_size'),
        'test_set_normal': doc.get('test_set_normal'),
        'test_set_malicious': doc.get('test_set_malicious'),
        'extra_good_pcaps': doc.get('extra_good_pcaps', 0),
        'extra_bad_pcaps': doc.get('extra_bad_pcaps', 0),
        'local_normal_flows': doc.get('local_normal_flows'),
        'local_malicious_flows': doc.get('local_malicious_flows'),
        'extra_normal_flows': doc.get('extra_normal_flows'),
        'extra_malicious_flows': doc.get('extra_malicious_flows'),
        'extra_normal_packets': doc.get('extra_normal_packets'),
        'extra_malicious_packets': doc.get('extra_malicious_packets'),
        'merged_session_ids': doc.get('merged_session_ids') or [],
        'merged_sessions': _merged_sessions_for_run_doc(doc, username),
        'include_labeled_captures': doc.get('include_labeled_captures', True),
        'created_at': _utc_iso(doc.get('created_at')),
        'can_restore': can_restore,
    }


@app.route('/api/train/runs', methods=['GET'])
def train_runs_list():
    denied = _require_admin()
    if denied:
        return denied
    username = session.get('username')
    cursor = (
        mongo.db.model_runs.find({'username': username})
        .sort('created_at', -1)
        .limit(15)
    )
    active_fp = _file_fingerprint(_model_pkl_path())
    deployed = read_deployed_model_info()
    items = []
    active_run_id = None
    for doc in cursor:
        item = _serialize_model_run_doc(doc, username, active_fp=active_fp)
        if item.get('is_active'):
            active_run_id = item['id']
        items.append(item)
    return jsonify({
        'items': items,
        'active_model': {
            'run_id': active_run_id,
            'model_algorithm': deployed.get('model_algorithm', MODEL_ALGORITHM_NAME),
            'model_algorithm_label': deployed.get('model_algorithm_label', MODEL_ALGORITHM_LABEL),
        },
    }), 200


@app.route('/api/train/runs/<run_id>', methods=['GET'])
def train_run_detail(run_id):
    """训练记录详情；缺失基线对比时按当时样本现场补算。"""
    denied = _require_admin()
    if denied:
        return denied
    try:
        oid = ObjectId(str(run_id))
    except InvalidId:
        return jsonify({'error': '无效的训练记录 ID'}), 400
    doc = mongo.db.model_runs.find_one({
        '_id': oid,
        'username': session.get('username'),
    })
    if not doc:
        return jsonify({'error': '训练记录不存在'}), 404
    active_fp = _file_fingerprint(_model_pkl_path())
    run_item = _serialize_model_run_doc(
        doc,
        session.get('username'),
        active_fp=active_fp,
        ensure_baseline=True,
    )
    return jsonify({'run': run_item}), 200


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
    log_operation(
        mongo, 'train_restore',
        target_type='model_run',
        target_id=str(oid),
        detail=rel,
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


@app.route('/api/admin/users', methods=['POST'])
def admin_users_create():
    """管理员创建新用户。"""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', password)
    role = (data.get('role') or 'user').strip()

    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    if len(username) < 3 or len(username) > 10:
        return jsonify({'error': '用户名长度应为 3-10 个字符'}), 400
    if len(password) < 6 or len(password) > 16:
        return jsonify({'error': '密码长度应为 6-16 个字符'}), 400
    if password != confirm_password:
        return jsonify({'error': '两次输入的密码不一致'}), 400
    if role not in ('admin', 'user'):
        return jsonify({'error': '角色须为 admin 或 user'}), 400
    if mongo.db.users.find_one({'username': username}):
        return jsonify({'error': '用户名已存在'}), 400

    ins = mongo.db.users.insert_one({
        'username': username,
        'password': generate_password_hash(password),
        'role': role,
        'status': USER_STATUS_ACTIVE,
    })
    new_id = str(ins.inserted_id)
    log_operation(
        mongo, 'admin_create_user',
        target_type='user',
        target_id=new_id,
        detail=f'创建用户 {username}，role={role}',
    )
    return jsonify({
        'message': '用户创建成功',
        'user': {
            'id': new_id,
            'username': username,
            'role': role,
            'status': USER_STATUS_ACTIVE,
        },
    }), 201


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
    parts = []
    if 'password' in updates:
        parts.append('重置密码')
    if 'status' in updates:
        parts.append(f"status={updates['status']}")
    log_operation(
        mongo, 'admin_update_user',
        target_type='user',
        target_id=user_id,
        detail='，'.join(parts),
    )
    return jsonify({'message': '已更新'}), 200


@app.route('/api/admin/operation-logs', methods=['GET'])
def admin_operation_logs():
    """管理员查询操作审计日志（最近 N 条）。"""
    denied = _require_admin()
    if denied:
        return denied
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
    except (TypeError, ValueError):
        limit = 50
    cursor = (
        mongo.db.operation_logs.find()
        .sort('created_at', -1)
        .limit(limit)
    )
    items = []
    for doc in cursor:
        items.append({
            'id': str(doc['_id']),
            'username': doc.get('username'),
            'action': doc.get('action'),
            'target_type': doc.get('target_type'),
            'target_id': doc.get('target_id'),
            'detail': doc.get('detail'),
            'success': doc.get('success', True),
            'ip': doc.get('ip'),
            'created_at': doc['created_at'].isoformat() if doc.get('created_at') else None,
        })
    return jsonify({'items': items, 'count': len(items)}), 200


@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({'status': 'ok'}), 200
