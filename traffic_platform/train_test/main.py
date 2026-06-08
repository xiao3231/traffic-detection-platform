#!/usr/bin/env python
# -*- coding:utf-8 -*-

import numpy as np
# from scapy.main import _validate_local
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB, BernoulliNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC, SVC
import joblib
from sklearn import preprocessing, model_selection
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
import matplotlib.pyplot as plt
import warnings
import os

from .get_goodx import GetGoodx
from .get_feature import GetFeature
from .get_badx import GetBadx
from .feature_schema import FEATURE_NAMES, LABEL_MALICIOUS, LABEL_SAFE
import pprint
import argparse

MODEL_ALGORITHM_NAME = 'RandomForest'
MODEL_ALGORITHM_LABEL = '随机森林 (RandomForest)'

DATASET = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dataset')
GOOD_DATASET_PATH = os.path.join(DATASET, 'goodx.csv')
BAD_DATASET_PATH = os.path.join(DATASET, 'badx.csv')
# BAD_PCAP_PATH=os.path.join(DATASET, "danger_pcap")

DEFAULT_BAD_PCAP_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "danger_pcap\\2018-05-03_win12.pcap")


def parse_args():  # 命令行参数解析器
    desc = "Malicious traffic detection paltform"
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument('--updata_goodset', type=bool, default=False, help='是否抓取正常流量数据')
    parser.add_argument('--updata_badset', type=bool, default=False, help='是否更新恶意流量数据')

    parser.add_argument('--num_epoch', type=int, default=5, help='抓取数据流量的次数')
    parser.add_argument('--num_ev', type=int, default=20, help='每次抓取流量包的数量')

    parser.add_argument('--train', action='store_true', required=True, help='训练并输出结果')

    # parser.add_argument('--good_dir',type=GOOD_DATASET_PATH,help='正常流量数据文件存放地址')
    # parser.add_argument('--bad_dir',type=BAD_DATASET_PATH,help='恶意流量数据文件存放地址')
    # parser.add_argument('--bad_pcap_dir',type=BAD_DATASET_PATH,default=DEFAULT_BAD_PCAP_PATH,help='恶意流量数据文件存放地址')

    parser.add_argument('--good_dir', type=str, default=str(GOOD_DATASET_PATH), help='正常流量数据文件存放地址')
    parser.add_argument('--bad_dir', type=str, default=str(BAD_DATASET_PATH), help='恶意流量数据文件存放地址')
    parser.add_argument('--bad_pcap_dir', type=str, default=str(DEFAULT_BAD_PCAP_PATH), help='恶意流量数据文件存放地址')

    parser.add_argument('--ignore_warning', type=bool, default=True, help='是否忽略警告')

    args = parser.parse_args()
    validate_args(args)

    return args


def validate_args(args):
    # 打印参数
    print('validating arguments...')
    pprint.pprint(args.__dict__)
    if args.updata_badset:
        print(args.bad_pcap_dir)
        assert os.path.exists(args.bad_pcap_dir)  # 检查恶意流量pcap文件是否存在


def plot_confusion_mat(confusion_mat):
    # 注意必须是imshow()
    plt.imshow(confusion_mat, interpolation='nearest', cmap=plt.cm.Paired)
    plt.title('Confusion Matrix')
    plt.colorbar()
    tick_marks = np.arange(4)
    plt.xticks(tick_marks, tick_marks)
    plt.yticks(tick_marks, tick_marks)
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()


def _evaluate_binary_classifier(clf, x_test, y_test):
    """测试集评估：混淆矩阵 + 安全/恶意各类 Precision、Recall、F1。"""
    y_true = y_test.ravel()
    y_pred = clf.predict(x_test)
    cm = confusion_matrix(y_true, y_pred, labels=[LABEL_MALICIOUS, LABEL_SAFE])
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=[LABEL_MALICIOUS, LABEL_SAFE], zero_division=0
    )
    return {
        'confusion_matrix': {
            'labels': ['malicious', 'safe'],
            'matrix': cm.tolist(),
            'description': '行=真实标签，列=预测；顺序 malicious(0), safe(1)',
        },
        'malicious_precision': float(prec[0]),
        'malicious_recall': float(rec[0]),
        'malicious_f1': float(f1[0]),
        'safe_precision': float(prec[1]),
        'safe_recall': float(rec[1]),
        'safe_f1': float(f1[1]),
        'accuracy': float(accuracy_score(y_true, y_pred)),
    }


def _classifier_metrics_row(clf, x_train, y_train, x_test, y_test, name, label, is_primary=False):
    """在同一划分上汇总单分类器的训练/测试指标（供基线对比表）。"""
    y_train_flat = y_train.ravel()
    eval_metrics = _evaluate_binary_classifier(clf, x_test, y_test)
    return {
        'name': name,
        'label': label,
        'is_primary': bool(is_primary),
        'train_score': float(clf.score(x_train, y_train_flat)),
        'test_score': float(eval_metrics['accuracy']),
        'malicious_precision': eval_metrics['malicious_precision'],
        'malicious_recall': eval_metrics['malicious_recall'],
        'malicious_f1': eval_metrics['malicious_f1'],
        'safe_precision': eval_metrics['safe_precision'],
        'safe_recall': eval_metrics['safe_recall'],
        'safe_f1': eval_metrics['safe_f1'],
    }


def _build_baseline_comparison(x_train, y_train, x_test, y_test, primary_clf):
    """在相同 7:3 划分上训练逻辑回归、决策树，与随机森林对比。"""
    y_train_flat = y_train.ravel()
    models = [
        _classifier_metrics_row(
            primary_clf, x_train, y_train, x_test, y_test,
            MODEL_ALGORITHM_NAME, MODEL_ALGORITHM_LABEL, is_primary=True,
        ),
    ]

    lr = LogisticRegression(
        max_iter=2000,
        class_weight='balanced',
        random_state=42,
    )
    lr.fit(x_train, y_train_flat)
    models.append(_classifier_metrics_row(
        lr, x_train, y_train, x_test, y_test,
        'LogisticRegression', '逻辑回归',
    ))

    dt = DecisionTreeClassifier(
        max_depth=100,
        class_weight='balanced',
        random_state=42,
    )
    dt.fit(x_train, y_train_flat)
    models.append(_classifier_metrics_row(
        dt, x_train, y_train, x_test, y_test,
        'DecisionTree', '决策树',
    ))

    return {
        'description': '逻辑回归、决策树与随机森林使用相同 7:3 划分；仅随机森林写入 model.pkl',
        'models': models,
    }


def _feature_importance_list(model, top_n=12):
    if not hasattr(model, 'feature_importances_'):
        return []
    names = FEATURE_NAMES
    if len(model.feature_importances_) != len(names):
        names = [f'f{i}' for i in range(len(model.feature_importances_))]
    pairs = sorted(
        zip(names, model.feature_importances_),
        key=lambda x: -float(x[1]),
    )
    return [{'name': n, 'importance': float(v)} for n, v in pairs[:top_n]]


def _binary_label_counts(y):
    """统计二分类标签：1=正常，0=恶意。返回 (normal, malicious, total)。"""
    flat = np.asarray(y).ravel()
    malicious = int(np.sum(flat == 0))
    normal = int(np.sum(flat == 1))
    return normal, malicious, int(flat.size)


def train(x, y):
    """随机森林训练并保存 model.pkl。"""
    try:
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=0.3, random_state=42, stratify=y
        )
    except ValueError:
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=0.3, random_state=42
        )
    y_train_flat = y_train.ravel()
    y_test_flat = y_test.ravel()
    sample_normal, sample_malicious, sample_total = _binary_label_counts(y)
    train_normal, train_malicious, train_set_size = _binary_label_counts(y_train_flat)
    test_normal, test_malicious, test_set_size = _binary_label_counts(y_test_flat)

    rfc = RandomForestClassifier(
        criterion='gini',
        max_depth=100,
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced_subsample',
    )
    rfc.fit(x_train, y_train_flat)
    eval_metrics = _evaluate_binary_classifier(rfc, x_test, y_test)
    train_score = float(rfc.score(x_train, y_train_flat))
    test_score = float(eval_metrics['accuracy'])
    baseline_comparison = _build_baseline_comparison(x_train, y_train, x_test, y_test, rfc)

    print(f"训练集准确率: {train_score:.4f}  测试集准确率: {test_score:.4f}")
    print(f"混淆矩阵:\n{eval_metrics['confusion_matrix']['matrix']}")
    print('基线对比（测试集准确率）:')
    for row in baseline_comparison['models']:
        mark = ' [线上]' if row.get('is_primary') else ''
        print(f"  {row['label']}: {row['test_score']:.4f}{mark}")

    feature_importance = _feature_importance_list(rfc)
    model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'model.pkl')
    artifact = {
        'version': 2,
        'model': rfc,
        'feature_names': FEATURE_NAMES,
        'primary_algorithm': MODEL_ALGORITHM_NAME,
    }
    joblib.dump(artifact, model_path)
    print(f"模型已保存到: {model_path}")

    return {
        'train_score': train_score,
        'test_score': test_score,
        'feature_count': len(FEATURE_NAMES),
        'sample_total': sample_total,
        'sample_normal': sample_normal,
        'sample_malicious': sample_malicious,
        'train_set_size': train_set_size,
        'train_set_normal': train_normal,
        'train_set_malicious': train_malicious,
        'test_set_size': test_set_size,
        'test_set_normal': test_normal,
        'test_set_malicious': test_malicious,
        **eval_metrics,
        'feature_importance': feature_importance,
        'baseline_comparison': baseline_comparison,
        'model_algorithm': MODEL_ALGORITHM_NAME,
        'model_algorithm_label': MODEL_ALGORITHM_LABEL,
    }


def read_deployed_model_info():
    """读取当前 model.pkl 中的算法标识（供训练记录与检测页展示）。"""
    model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'model.pkl')
    if not os.path.isfile(model_path):
        return {
            'model_algorithm': MODEL_ALGORITHM_NAME,
            'model_algorithm_label': MODEL_ALGORITHM_LABEL,
        }
    try:
        loaded = joblib.load(model_path)
    except Exception:
        return {
            'model_algorithm': MODEL_ALGORITHM_NAME,
            'model_algorithm_label': MODEL_ALGORITHM_LABEL,
        }
    if isinstance(loaded, dict):
        algo = loaded.get('primary_algorithm')
        if algo:
            label = algo
            if algo == 'RandomForest':
                label = MODEL_ALGORITHM_LABEL
            return {'model_algorithm': str(algo), 'model_algorithm_label': label}
        model = loaded.get('model') or loaded.get('rf_model')
        if model is not None:
            cls = type(model).__name__
            if 'RandomForest' in cls:
                return {
                    'model_algorithm': MODEL_ALGORITHM_NAME,
                    'model_algorithm_label': MODEL_ALGORITHM_LABEL,
                }
            return {'model_algorithm': cls, 'model_algorithm_label': cls}
    cls = type(loaded).__name__
    return {'model_algorithm': cls, 'model_algorithm_label': cls}


def _load_classifier():
    model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'model.pkl')
    loaded = joblib.load(model_path)
    if isinstance(loaded, dict):
        if 'model' in loaded:
            return loaded['model']
        if 'rf_model' in loaded:
            return loaded['rf_model']
    return loaded


DEFAULT_MALICIOUS_PROB_THRESHOLD = 0.8
DEFAULT_MALICIOUS_RATIO_THRESHOLD = 0.2
THRESHOLD_RULE_TEXT = (
    '文件判为危险：存在流的恶意概率 ≥ 概率阈值，或硬分类恶意流占比 > 占比阈值；'
    '否则判为安全（非「任一流恶意即整包危险」）。'
)


def _malicious_proba_index(clf):
    if hasattr(clf, 'classes_'):
        classes = list(clf.classes_)
        if LABEL_MALICIOUS in classes:
            return classes.index(LABEL_MALICIOUS)
    return 0


def predicts(x):
    clf = _load_classifier()
    x_arr = np.asarray(x)
    if hasattr(clf, 'n_features_in_') and x_arr.ndim == 2 and x_arr.shape[1] != clf.n_features_in_:
        raise ValueError(
            f'特征维度 {x_arr.shape[1]} 与已加载模型 {clf.n_features_in_} 不一致，'
            '请在协议分析页执行一次「模型重训」后再检测。'
        )
    return clf.predict(x_arr)


def predicts_malicious_proba(x):
    """返回每条样本属于恶意类（标签 0）的概率。"""
    clf = _load_classifier()
    x_arr = np.asarray(x)
    if hasattr(clf, 'n_features_in_') and x_arr.ndim == 2 and x_arr.shape[1] != clf.n_features_in_:
        raise ValueError(
            f'特征维度 {x_arr.shape[1]} 与已加载模型 {clf.n_features_in_} 不一致，'
            '请在协议分析页执行一次「模型重训」后再检测。'
        )
    if not hasattr(clf, 'predict_proba'):
        preds = clf.predict(x_arr).ravel()
        return np.where(preds == LABEL_MALICIOUS, 1.0, 0.0).astype(float)
    proba = clf.predict_proba(x_arr)
    return proba[:, _malicious_proba_index(clf)].astype(float)


def evaluate_flows_decision(preds, probas, prob_threshold=None, ratio_threshold=None):
    """
    基于硬分类占比与恶意概率阈值的文件级判定。
    危险条件（满足其一）：max(P恶意) >= prob_threshold；或恶意硬分类流占比 > ratio_threshold。
    """
    prob_threshold = (
        DEFAULT_MALICIOUS_PROB_THRESHOLD
        if prob_threshold is None
        else float(prob_threshold)
    )
    ratio_threshold = (
        DEFAULT_MALICIOUS_RATIO_THRESHOLD
        if ratio_threshold is None
        else float(ratio_threshold)
    )
    pred_flat = np.asarray(preds).ravel()
    proba_flat = np.asarray(probas, dtype=float).ravel()
    n = int(pred_flat.size)
    if n == 0:
        return {
            'is_safe': True,
            'flow_count': 0,
            'malicious_flow_count': 0,
            'malicious_flow_ratio': 0.0,
            'high_prob_flow_count': 0,
            'max_malicious_prob': 0.0,
            'triggered_by_prob': False,
            'triggered_by_ratio': False,
            'prob_threshold': prob_threshold,
            'ratio_threshold': ratio_threshold,
            'rule_text': THRESHOLD_RULE_TEXT,
        }
    malicious_n = int(np.sum(pred_flat == LABEL_MALICIOUS))
    ratio = malicious_n / n
    max_prob = float(np.max(proba_flat))
    high_prob_n = int(np.sum(proba_flat >= prob_threshold))
    triggered_prob = max_prob >= prob_threshold
    triggered_ratio = ratio > ratio_threshold
    return {
        'is_safe': not (triggered_prob or triggered_ratio),
        'flow_count': n,
        'malicious_flow_count': malicious_n,
        'malicious_flow_ratio': ratio,
        'high_prob_flow_count': high_prob_n,
        'max_malicious_prob': max_prob,
        'triggered_by_prob': triggered_prob,
        'triggered_by_ratio': triggered_ratio,
        'prob_threshold': prob_threshold,
        'ratio_threshold': ratio_threshold,
        'rule_text': THRESHOLD_RULE_TEXT,
    }


def analyze_pcap(pcap_path, prob_threshold=None, ratio_threshold=None):
    """提取流特征并返回阈值判定结果及逐流预测。"""
    feats = GetFeature().MakeFeatures(pcap_path)
    if not feats:
        decision = evaluate_flows_decision([], [], prob_threshold, ratio_threshold)
        decision['flows'] = []
        return decision
    x_arr = np.array(feats, dtype=float)
    preds = predicts(x_arr)
    probas = predicts_malicious_proba(x_arr)
    decision = evaluate_flows_decision(preds, probas, prob_threshold, ratio_threshold)
    flows = []
    pred_list = preds.tolist() if hasattr(preds, 'tolist') else list(preds)
    for i, row in enumerate(feats):
        pi = int(pred_list[i]) if i < len(pred_list) else None
        mp = float(probas[i]) if i < len(probas) else None
        flows.append({
            'index': i + 1,
            'features': [float(v) for v in row],
            'prediction': pi,
            'prediction_label': '安全' if pi == LABEL_SAFE else ('危险' if pi == LABEL_MALICIOUS else '—'),
            'malicious_prob': mp,
            'high_risk': bool(mp is not None and mp >= decision['prob_threshold']),
        })
    decision['flows'] = flows
    return decision


def predicts_pcap(pcap_path):
    x = GetFeature().MakeFeatures(pcap_path)
    return predicts(x)  # true: safe file false: dangerous file


def _pcap_packet_count(pcap_path):
    """统计 pcap 文件中的包数（用于训练样本来源展示）。"""
    try:
        from scapy.all import rdpcap
        return int(len(rdpcap(pcap_path)))
    except Exception:
        return 0


def _build_sample_source_stats(
    local_good_flows,
    local_bad_flows,
    extra_good_pcaps=0,
    extra_bad_pcaps=0,
    extra_good_flows=0,
    extra_bad_flows=0,
    extra_good_packets=0,
    extra_bad_packets=0,
):
    return {
        'local_normal_flows': int(local_good_flows),
        'local_malicious_flows': int(local_bad_flows),
        'extra_normal_pcaps': int(extra_good_pcaps),
        'extra_malicious_pcaps': int(extra_bad_pcaps),
        'extra_normal_flows': int(extra_good_flows),
        'extra_malicious_flows': int(extra_bad_flows),
        'extra_normal_packets': int(extra_good_packets),
        'extra_malicious_packets': int(extra_bad_packets),
    }


def run(good_filename=None, bad_filename=None):
    good_filename = good_filename or GOOD_DATASET_PATH
    bad_filename = bad_filename or BAD_DATASET_PATH
    goodx = GetFeature().MakeFeatures(good_filename)
    badx = GetFeature().MakeFeatures(bad_filename)
    source_stats = _build_sample_source_stats(
        local_good_flows=len(goodx),
        local_bad_flows=len(badx),
    )
    return _train_from_feature_lists(goodx, badx, source_stats=source_stats)


def run_with_extra_pcaps(
    good_filename=None,
    bad_filename=None,
    extra_good_pcaps=None,
    extra_bad_pcaps=None,
):
    """
    在默认 goodx/badx 上合并若干已标注 pcap 提取的特征后再训练。
    extra_* 为服务器上 pcap 绝对路径列表。
    """
    good_filename = good_filename or GOOD_DATASET_PATH
    bad_filename = bad_filename or BAD_DATASET_PATH
    gf = GetFeature()
    goodx = gf.MakeFeatures(good_filename)
    badx = gf.MakeFeatures(bad_filename)
    local_good_flows = len(goodx)
    local_bad_flows = len(badx)

    extra_good_pcaps_n = 0
    extra_bad_pcaps_n = 0
    extra_good_flows = 0
    extra_bad_flows = 0
    extra_good_packets = 0
    extra_bad_packets = 0

    for p in extra_good_pcaps or []:
        if p and os.path.isfile(p):
            feats = gf.MakeFeatures(p)
            extra_good_pcaps_n += 1
            extra_good_flows += len(feats)
            extra_good_packets += _pcap_packet_count(p)
            goodx.extend(feats)
    for p in extra_bad_pcaps or []:
        if p and os.path.isfile(p):
            feats = gf.MakeFeatures(p)
            extra_bad_pcaps_n += 1
            extra_bad_flows += len(feats)
            extra_bad_packets += _pcap_packet_count(p)
            badx.extend(feats)

    source_stats = _build_sample_source_stats(
        local_good_flows=local_good_flows,
        local_bad_flows=local_bad_flows,
        extra_good_pcaps=extra_good_pcaps_n,
        extra_bad_pcaps=extra_bad_pcaps_n,
        extra_good_flows=extra_good_flows,
        extra_bad_flows=extra_bad_flows,
        extra_good_packets=extra_good_packets,
        extra_bad_packets=extra_bad_packets,
    )
    return _train_from_feature_lists(goodx, badx, source_stats=source_stats)


def _encode_feature_matrix(goodx, badx):
    """将正负样本特征列表编码为模型可用的矩阵。"""
    if not goodx or not badx:
        raise ValueError('正样本或负样本特征为空，无法训练（请检查数据集路径与 pcap）')
    goody = [1] * len(goodx)
    bady = [0] * len(badx)
    feature_len = len(goodx[0])
    x = np.append(goodx, badx).reshape(-1, feature_len)
    y = np.append(goody, bady).reshape(-1, 1)
    x_encoded = np.empty(x.shape)
    for i, item in enumerate(x[0]):
        if str(item).isdigit():
            x_encoded[:, i] = x[:, i]
        else:
            encoder = preprocessing.LabelEncoder()
            x_encoded[:, i] = encoder.fit_transform(x[:, i])
    return shuffle(x_encoded, y)


def compute_baseline_metrics(
    good_filename=None,
    bad_filename=None,
    extra_good_pcaps=None,
    extra_bad_pcaps=None,
):
    """仅计算随机森林 / 逻辑回归 / 决策树基线对比，不写入 model.pkl。"""
    good_filename = good_filename or GOOD_DATASET_PATH
    bad_filename = bad_filename or BAD_DATASET_PATH
    gf = GetFeature()
    goodx = gf.MakeFeatures(good_filename)
    badx = gf.MakeFeatures(bad_filename)
    for p in extra_good_pcaps or []:
        if p and os.path.isfile(p):
            goodx.extend(gf.MakeFeatures(p))
    for p in extra_bad_pcaps or []:
        if p and os.path.isfile(p):
            badx.extend(gf.MakeFeatures(p))
    x_encoded, y = _encode_feature_matrix(goodx, badx)
    try:
        x_train, x_test, y_train, y_test = train_test_split(
            x_encoded, y, test_size=0.3, random_state=42, stratify=y
        )
    except ValueError:
        x_train, x_test, y_train, y_test = train_test_split(
            x_encoded, y, test_size=0.3, random_state=42
        )
    rfc = RandomForestClassifier(
        criterion='gini',
        max_depth=100,
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced_subsample',
    )
    rfc.fit(x_train, y_train.ravel())
    return _build_baseline_comparison(x_train, y_train, x_test, y_test, rfc)


def _train_from_feature_lists(goodx, badx, source_stats=None):
    x_encoded, y = _encode_feature_matrix(goodx, badx)
    print("特征集大小{}".format(x_encoded.shape))
    print("输出集大小{}".format(y.shape))
    result = train(x_encoded, y)
    if source_stats:
        result.update(source_stats)
    return result


def analysis(
    file_name,
    save_path,
    num_epoch=20,
    num_ev=50,
    prob_threshold=None,
    ratio_threshold=None,
):
    """分析 PCAP；返回是否安全（bool）。文件级判定采用可配置概率/占比阈值。"""
    warnings.filterwarnings("ignore")
    try:
        out = analyze_pcap(file_name, prob_threshold, ratio_threshold)
        return bool(out.get('is_safe', True))
    except Exception as e:
        print(f"预测出错: {e}")
        import traceback
        traceback.print_exc()
        return True


def main():
    args = parse_args()
    if args.ignore_warning:
        warnings.filterwarnings("ignore")  # 忽略警告
    if args.updata_goodset:
        # 获取正样本
        get_goodx = GetGoodx(args.good_dir, args.num_epoch, args.num_ev)
        get_goodx.get()
    if args.updata_badset:
        # 获取负样本
        get_badx = GetBadx(args.bad_dir, args.bad_pcap_dir, args.num_epoch * args.num_ev)
        get_badx.get()
    if args.train:
        run(args.good_dir, args.bad_dir)


if __name__ == "__main__":
    main()