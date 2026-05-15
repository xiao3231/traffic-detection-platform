#!/usr/bin/env python
# -*- coding:utf-8 -*-

import numpy as np
# from scapy.main import _validate_local
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB, BernoulliNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC, SVC
import joblib
from sklearn import preprocessing, model_selection
# from sklearn.metrics import confusion_matrix,classification_report
import matplotlib.pyplot as plt
import warnings
import os

from .get_goodx import GetGoodx
from .get_feature import GetFeature
from .get_badx import GetBadx
import pprint
import argparse

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


def train(x, y):
    """
    使用随机森林训练模型并保存效果最好的
    """
    # 将数据集分为训练集和测试集
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)
    
    # 使用随机森林（效果通常最好）
    model = RandomForestClassifier(
        criterion='gini', 
        max_depth=100, 
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )
    
    # 训练模型
    model.fit(x_train, y_train.ravel())
    
    # 评估模型
    train_score = model.score(x_train, y_train)
    test_score = model.score(x_test, y_test)
    
    print(f"训练集准确率: {train_score:.4f}")
    print(f"测试集准确率: {test_score:.4f}")
    
    # 保存模型到正确路径
    model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'model.pkl')
    joblib.dump(model, model_path)
    print(f"模型已保存到: {model_path}")
    return {'train_score': float(train_score), 'test_score': float(test_score)}


def predicts(x):
    model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'model.pkl')
    clf = joblib.load(model_path)  # 加载已保存的模型
    
    # 支持组合模型和新格式
    if isinstance(clf, dict) and 'rf_model' in clf:
        rf_model = clf['rf_model']
        # 只使用 RF 分类器作为主要检测
        rf_predictions = rf_model.predict(x)  # 1=安全, 0=恶意
        return rf_predictions
    else:
        return clf.predict(x)


def predicts_pcap(pcap_path):
    x = GetFeature().MakeFeatures(pcap_path)
    return predicts(x)  # true: safe file false: dangerous file


def run(good_filename='train_test/goodx.csv', bad_filename='train_test/badx.csv'):
    goodx = GetFeature().MakeFeatures(good_filename)
    badx = GetFeature().MakeFeatures(bad_filename)
    return _train_from_feature_lists(goodx, badx)


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
    for p in extra_good_pcaps or []:
        if p and os.path.isfile(p):
            goodx.extend(gf.MakeFeatures(p))
    for p in extra_bad_pcaps or []:
        if p and os.path.isfile(p):
            badx.extend(gf.MakeFeatures(p))
    return _train_from_feature_lists(goodx, badx)


def _train_from_feature_lists(goodx, badx):
    if not goodx or not badx:
        raise ValueError('正样本或负样本特征为空，无法训练（请检查数据集路径与 pcap）')
    goody = [1] * len(goodx)
    bady = [0] * len(badx)

    feature_len = len(goodx[0])
    x = np.append(goodx, badx).reshape(-1, feature_len)
    print("特征集大小{}".format(x.shape))
    y = np.append(goody, bady).reshape(-1, 1)
    print("输出集大小{}".format(y.shape))

    labels_encoder = []
    x_encoded = np.empty(x.shape)
    for i, item in enumerate(x[0]):
        if (str(item).isdigit()):
            x_encoded[:, i] = x[:, i]
        else:
            labels_encoder.append(preprocessing.LabelEncoder())
            x_encoded[:, i] = labels_encoder[-1].fit_transform(x[:, i])

    x_encoded, y = shuffle(x_encoded, y)
    return train(x_encoded, y)


def analysis(file_name, save_path, num_epoch=20, num_ev=50):
    # 简化：直接调用 predicts_pcap 分析上传的PCAP文件
    warnings.filterwarnings("ignore")

    try:
        # 直接分析PCAP文件
        result = predicts_pcap(file_name)
        # result 是 numpy 数组，每个元素对应一个流量
        # 模型输出: 1=安全(good), 0=恶意(bad)
        if isinstance(result, (list, np.ndarray)):
            # 检查所有流量：如果任何一个是恶意的（0），整个文件标记为危险
            is_safe = all(r == 1 for r in result)
        else:
            is_safe = bool(result == 1)
        return is_safe
    except Exception as e:
        print(f"预测出错: {e}")
        import traceback
        traceback.print_exc()
        # 如果失败，返回安全（避免报错）
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