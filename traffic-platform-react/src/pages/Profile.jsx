import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import { apiUrl, readJsonResponse } from '../api'

export default function Profile() {
  const [user, setUser] = useState(null)
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
      </div>

      <style>{`
        .profile-container {
          min-height: 100vh;
          background: #0D0D0D;
        }
        .profile-content {
          max-width: 600px;
          margin: 40px auto;
          padding: 0 20px;
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
      `}</style>
    </div>
  )
}
