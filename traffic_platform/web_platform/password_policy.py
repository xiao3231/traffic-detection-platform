"""用户密码强度校验（注册、创建用户、修改/重置密码共用）。"""
import re

PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 32

_WEAK_PASSWORDS = frozenset({
    '12345678', '123456789', '1234567890', 'password', 'password1', 'password123',
    'qwerty123', 'qwertyui', 'admin123', 'abc12345', '11111111', '00000000',
    '87654321', 'a1234567', '1234567a', 'iloveyou', 'welcome1', 'p@ssw0rd',
    'passw0rd', 'admin888', '123123123', '66666666', '88888888', 'qwer1234',
    'asdf1234', 'zxcv1234', '1qaz2wsx', 'aa123456', 'abc123456',
})


def password_policy_hint():
    return (
        f'密码须 {PASSWORD_MIN_LEN}-{PASSWORD_MAX_LEN} 位，且同时包含字母与数字；'
        f'不能与用户名相同，不能使用常见弱密码。'
    )


def validate_password(password, username=None):
    """返回 (是否通过, 错误说明)。"""
    if not password:
        return False, '密码不能为空'
    if len(password) < PASSWORD_MIN_LEN or len(password) > PASSWORD_MAX_LEN:
        return False, f'密码长度应为 {PASSWORD_MIN_LEN}-{PASSWORD_MAX_LEN} 个字符'
    if not re.search(r'[A-Za-z]', password):
        return False, '密码须包含至少一个字母'
    if not re.search(r'\d', password):
        return False, '密码须包含至少一个数字'
    if len(set(password)) == 1:
        return False, '密码不能为同一字符重复'
    uname = (username or '').strip()
    if uname and password.lower() == uname.lower():
        return False, '密码不能与用户名相同'
    if password.lower() in _WEAK_PASSWORDS:
        return False, '密码过于简单，请使用更复杂的组合'
    return True, None
