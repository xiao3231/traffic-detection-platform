import sys; sys.path.insert(0, '.')
from traffic_platform.train_test.get_feature import GetFeature
import numpy as np

bad_features = GetFeature().MakeFeatures('traffic_platform/train_test/dataset/badx.csv')
good_features = GetFeature().MakeFeatures('traffic_platform/train_test/dataset/goodx.csv')

bad_arr = np.array(bad_features)
good_arr = np.array(good_features)

print('恶意 time_mean: min=%.1f max=%.1f mean=%.1f' % (bad_arr[:,2].min(), bad_arr[:,2].max(), bad_arr[:,2].mean()))
print('正常 time_mean: min=%.1f max=%.1f mean=%.1f' % (good_arr[:,2].min(), good_arr[:,2].max(), good_arr[:,2].mean()))
print('恶意 time_std: min=%.1f max=%.1f mean=%.1f' % (bad_arr[:,3].min(), bad_arr[:,3].max(), bad_arr[:,3].mean()))
print('正常 time_std: min=%.1f max=%.1f mean=%.1f' % (good_arr[:,3].min(), good_arr[:,3].max(), good_arr[:,3].mean()))
print('恶意 TLS: min=%.1f max=%.1f mean=%.1f' % (bad_arr[:,11].min(), bad_arr[:,11].max(), bad_arr[:,11].mean()))
print('正常 TLS: min=%.1f max=%.1f mean=%.1f' % (good_arr[:,11].min(), good_arr[:,11].max(), good_arr[:,11].mean()))

# 测试恶意pcap的特征
print('\n=== test8-malicious.pcap 特征 ===')
malicious_features = GetFeature()._make_features_from_pcap('traffic_platform/web_platform/upload/test8-malicious.pcap')
print(malicious_features)
