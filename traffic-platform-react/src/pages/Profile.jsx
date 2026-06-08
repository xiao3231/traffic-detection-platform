import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import { apiUrl, readJsonResponse } from '../api'

export default function Profile() {
  const [user, setUser] = useState(null)
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [pwdMsg, setPwdMsg] = useState(null)
  const [pwdError, setPwdError] = useState(null)
  const [pwdLoading, setPwdLoading] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    fetch(apiUrl('/api/check-session'), { credentials: 'include' })
      .then(res => readJsonResponse(res))
      .then(data => {
        if (!data.logged_in) {
          navigate('/login')
        } else {
          setUser(data)
        }
      })
  }, [navigate])

  const handleChangePassword = async (e) => {
    e.preventDefault()
    setPwdMsg(null)
    setPwdError(null)
    setPwdLoading(true)
    try {
      const res = await fetch(apiUrl('/api/profile/change-password'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
          confirm_password: confirmPassword,
        }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '修改失败')
      setPwdMsg(data.message || '密码修改成功')
      setOldPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      setPwdError(err.message)
    } finally {
      setPwdLoading(false)
    }
  }

  if (!user) return null

  return (
    <div className="profile-container">
      <Header />

      <div className="profile-content">
        <h1>个人中心</h1>
        <div className="profile-card">
          <div className="avatar-large">
            <span>{user.username?.charAt(0).toUpperCase()}</span>
          </div>
          <div className="info-item">
            <label>用户名</label>
            <span>{user.username}</span>
          </div>
          <div className="info-item">
            <label>身份</label>
            <span className={`role-tag ${user.role}`}>
              {user.role === 'admin' ? '管理员' : '普通用户'}
            </span>
          </div>
        </div>

        <div className="profile-card pwd-card">
          <h2>修改密码</h2>
          <p className="pwd-hint">新密码长度 6～16 位，修改成功后请妥善保管。</p>
          <form onSubmit={handleChangePassword}>
            <div className="field">
              <label htmlFor="old-pwd">原密码</label>
              <input
                id="old-pwd"
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                placeholder="请输入当前密码"
                required
                autoComplete="current-password"
              />
            </div>
            <div className="field">
              <label htmlFor="new-pwd">新密码</label>
              <input
                id="new-pwd"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="6-16 个字符"
                required
                minLength={6}
                maxLength={16}
                autoComplete="new-password"
              />
            </div>
            <div className="field">
              <label htmlFor="confirm-pwd">确认新密码</label>
              <input
                id="confirm-pwd"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入新密码"
                required
                autoComplete="new-password"
              />
            </div>
            {pwdError && <div className="pwd-banner error">{pwdError}</div>}
            {pwdMsg && <div className="pwd-banner success">{pwdMsg}</div>}
            <button type="submit" className="pwd-submit" disabled={pwdLoading}>
              {pwdLoading ? '提交中…' : '确认修改'}
            </button>
          </form>
        </div>
      </div>

      <style>{`
        .profile-container {
          min-height: 100vh;
          background: #0D0D0D;
        }
        .profile-content {
          max-width: 600px;
          margin: 40px auto;
          padding: 0 20px 60px;
        }
        .profile-content h1 {
          color: #fff;
          margin-bottom: 30px;
          font-size: 28px;
        }
        .profile-card {
          background: #1A1A1A;
          border-radius: 20px;
          padding: 40px;
          border: 1px solid #333;
          box-shadow: 0 20px 50px rgba(0,0,0,0.5);
          margin-bottom: 24px;
        }
        .pwd-card h2 {
          color: #fff;
          font-size: 18px;
          margin: 0 0 8px;
          font-weight: 600;
        }
        .pwd-hint {
          color: #888;
          font-size: 13px;
          margin: 0 0 24px;
        }
        .avatar-large {
          width: 100px;
          height: 100px;
          border-radius: 50%;
          background: linear-gradient(135deg, #AB08E3 0%, #930AC3 100%);
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 30px;
          border: 3px solid rgba(171, 8, 227, 0.3);
        }
        .avatar-large span {
          color: white;
          font-size: 40px;
          font-weight: 600;
        }
        .info-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 18px 0;
          border-bottom: 1px solid #333;
        }
        .info-item:last-child {
          border-bottom: none;
        }
        .info-item label {
          color: #A0A0A0;
          font-size: 15px;
        }
        .info-item span {
          color: #fff;
          font-size: 16px;
          font-weight: 500;
        }
        .role-tag {
          padding: 6px 16px;
          border-radius: 20px;
          font-size: 14px;
          font-weight: 600;
        }
        .role-tag.admin {
          background: linear-gradient(135deg, #AB08E3 0%, #930AC3 100%);
          color: white;
        }
        .role-tag.user {
          background: #333;
          color: #A0A0A0;
        }
        .field {
          margin-bottom: 16px;
        }
        .field label {
          display: block;
          color: #aaa;
          font-size: 13px;
          margin-bottom: 8px;
        }
        .field input {
          width: 100%;
          box-sizing: border-box;
          padding: 12px 14px;
          border-radius: 10px;
          border: 1px solid #444;
          background: #111;
          color: #fff;
          font-size: 15px;
        }
        .field input:focus {
          outline: none;
          border-color: #ab08e3;
        }
        .pwd-banner {
          padding: 10px 14px;
          border-radius: 10px;
          font-size: 13px;
          margin-bottom: 16px;
        }
        .pwd-banner.error {
          background: rgba(255, 80, 80, 0.12);
          border: 1px solid rgba(255, 80, 80, 0.35);
          color: #ff8a8a;
        }
        .pwd-banner.success {
          background: rgba(80, 200, 120, 0.12);
          border: 1px solid rgba(80, 200, 120, 0.35);
          color: #7dcea0;
        }
        .pwd-submit {
          width: 100%;
          padding: 12px;
          border: none;
          border-radius: 10px;
          background: linear-gradient(90deg, #ab08e3, #c73ef5);
          color: #fff;
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
        }
        .pwd-submit:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
      `}</style>
    </div>
  )
}
