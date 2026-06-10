const PASSWORD_MIN_LEN = 8
const PASSWORD_MAX_LEN = 32

const WEAK_PASSWORDS = new Set([
  '12345678', '123456789', '1234567890', 'password', 'password1', 'password123',
  'qwerty123', 'qwertyui', 'admin123', 'abc12345', '11111111', '00000000',
  '87654321', 'a1234567', '1234567a', 'iloveyou', 'welcome1', 'p@ssw0rd',
  'passw0rd', 'admin888', '123123123', '66666666', '88888888', 'qwer1234',
  'asdf1234', 'zxcv1234', '1qaz2wsx', 'aa123456', 'abc123456',
])

export const PASSWORD_POLICY_HINT =
  `密码须 ${PASSWORD_MIN_LEN}-${PASSWORD_MAX_LEN} 位，且同时包含字母与数字；不能与用户名相同，不能使用常见弱密码。`

/** @returns {string|null} 不通过时返回错误说明 */
export function validatePassword(password, username = '') {
  if (!password) return '密码不能为空'
  if (password.length < PASSWORD_MIN_LEN || password.length > PASSWORD_MAX_LEN) {
    return `密码长度应为 ${PASSWORD_MIN_LEN}-${PASSWORD_MAX_LEN} 个字符`
  }
  if (!/[A-Za-z]/.test(password)) return '密码须包含至少一个字母'
  if (!/\d/.test(password)) return '密码须包含至少一个数字'
  if (new Set(password).size === 1) return '密码不能为同一字符重复'
  const uname = String(username || '').trim()
  if (uname && password.toLowerCase() === uname.toLowerCase()) {
    return '密码不能与用户名相同'
  }
  if (WEAK_PASSWORDS.has(password.toLowerCase())) {
    return '密码过于简单，请使用更复杂的组合'
  }
  return null
}

export { PASSWORD_MIN_LEN, PASSWORD_MAX_LEN }
