# -*- coding: utf-8 -*-
"""
集中配置
========
所有路径、端口、默认参数、日志级别集中管理，支持环境变量覆盖（便于 Docker 部署）。
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(DATA_DIR, "alerts.db")

# 服务监听（Docker 中设为 0.0.0.0）
HOST = os.environ.get("NIDS_HOST", "127.0.0.1")
PORT = int(os.environ.get("NIDS_PORT", "5000"))

# 检测默认参数
DEFAULT_SENSITIVITY = float(os.environ.get("NIDS_SENSITIVITY", "0.5"))

# 日志
LOG_LEVEL = os.environ.get("NIDS_LOG_LEVEL", "INFO").upper()
LOG_FILE = os.path.join(LOG_DIR, "nids.log")

# 上传限制（字节）
MAX_UPLOAD_MB = int(os.environ.get("NIDS_MAX_UPLOAD_MB", "64"))
MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
