# -*- coding: utf-8 -*-
import sys
import os

# 确保当前包在路径中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask import Flask
from flask_pymongo import PyMongo
from flask_cors import CORS

app=Flask(__name__)

#加载配置文件内容
app.config.from_object('traffic_platform.web_platform.setting')

#初始化MongoDB
mongo = PyMongo(app)

# 启用 CORS，允许 React 前端访问
CORS(app, supports_credentials=True)

# 导入路由
from traffic_platform.web_platform.controller import message