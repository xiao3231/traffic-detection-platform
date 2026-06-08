# 恶意流量检测平台（Flask + React）

## 依赖由哪些文件决定？

| 环境 | 安装命令 | 依据文件 | 说明 |
|------|----------|----------|------|
| **Node / 前端** | 在 `traffic-platform-react/` 下执行 `npm install` | `traffic-platform-react/package.json`、`package-lock.json` | 锁文件会固定具体版本，保证与团队一致 |
| **Python / 后端** | 在项目根目录执行 `pip install -r requirements.txt` | 根目录 `requirements.txt` | 与 Flask、Scapy、sklearn、Mongo 等用法对齐 |

## 一键安装（推荐）

在项目**根目录** `scapy_machine_study_detetction_platform/` 下：

```bash
# 1) Python 虚拟环境（可选但推荐）
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2) 后端依赖
pip install -r requirements.txt

# 3) 前端依赖（必须在 frontend 子目录里执行 npm install）
cd traffic-platform-react
npm install
cd ..
```

## 运行前还需要

1. **MongoDB** 本地或远程可连，默认见 `traffic_platform/web_platform/setting.py` 里的 `MONGO_URI`。  
2. **启动后端**（在项目根目录，已激活 venv，并保证 `traffic_platform` 在 Python 路径中）：
   ```bash
   cd /path/to/scapy_machine_study_detetction_platform
   sudo env PYTHONPATH=. /Users/neptune/PythonProject/scapy_machine_study_detetction_platform/.venv/bin/python -m traffic_platform.web_platform.runserver

   ```
   默认一般为 **http://127.0.0.1:5000**（与 `vite.config.js` 里代理目标一致）。  
3. **启动前端**（另开终端）：
   ```bash
   cd traffic-platform-react
   npm run dev
   ```
   Vite 已代理 `/api` 到后端，见 `vite.config.js`。

## 说明

- 根目录的 `model.pkl`、`.venv/`、`node_modules/`、`upload/` 等已在 `.gitignore` 中，克隆后需在本地重新训练或放入模型、并执行上述安装命令。
- **流级特征为 17 维**（见 `traffic_platform/train_test/feature_schema.py`：基础统计 5 维 + 协议计数 7 维 + 行为扩展 5 维）。旧版 11/16 维 `model.pkl` 与当前代码不兼容，请在管理员「协议分析 → 模型重训」执行一次训练后再做 pcap 检测。
- 训练会输出：**混淆矩阵**、**恶意类 Recall/F1**、**特征重要性**、与 **逻辑回归 / 决策树** 的基线对比；`GET /api/train/feature-schema` 可查看各特征网安含义。
