# -*- coding: utf-8 -*-
"""操作/审计日志写入 operation_logs 集合。"""

from datetime import datetime, timezone

from flask import request, session


def client_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or ''


def log_operation(
    mongo,
    action,
    *,
    target_type=None,
    target_id=None,
    detail=None,
    username=None,
    user_id=None,
    success=True,
):
    """写入 operation_logs；失败仅打印，不影响主业务流程。"""
    try:
        mongo.db.operation_logs.insert_one({
            'username': username or session.get('username'),
            'user_id': user_id or session.get('user_id'),
            'action': action,
            'target_type': target_type,
            'target_id': str(target_id) if target_id is not None else None,
            'detail': detail,
            'success': bool(success),
            'ip': client_ip(),
            'created_at': datetime.now(timezone.utc),
        })
    except Exception as exc:
        print(f'operation_logs 写入失败: {exc}')
