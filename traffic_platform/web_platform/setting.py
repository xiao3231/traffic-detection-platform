# 配置数据库连接

#调试模式是否开启
DEBUG = True

#session必须要设置key
SECRET_KEY='random string'

#MongoDB配置
MONGO_URI='mongodb://localhost:27017/traffic_platform'

MAX_CONTENT_LENGTH = 10 * 1024 * 1024    # 指定要上传的文件的最大大小（以字节为单位）

"""
目录设置
"""
import os
# 使用绝对路径，无论从哪里运行都能找到
UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),  # setting.py所在目录
    'upload'
)
# 确保目录存在
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)      # 定义上传文件夹的路径