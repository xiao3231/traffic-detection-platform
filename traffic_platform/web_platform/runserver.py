from traffic_platform.web_platform import app
import logging

# 禁用 Flask 的 verbose 输出
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

if __name__ == "__main__":
    app.run(debug=False, use_reloader=False)