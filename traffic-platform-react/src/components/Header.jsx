import { useState, useEffect } from 'react'
import { useNavigate, Link, useLocation } from 'react-router-dom'
import { apiUrl, readJsonResponse } from '../api'
import './Header.css'

export default function Header() {
  const [user, setUser] = useState(null)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    fetch(apiUrl('/api/check-session'), { credentials: 'include' })
      .then(res => readJsonResponse(res))
      .then(data => {
        if (data.logged_in) {
          setUser({ username: data.username, role: data.role })
        }
      })
  }, [])

  const handleLogout = async () => {
    await fetch(apiUrl('/api/logout'), { method: 'POST', credentials: 'include' })
    navigate('/login')
  }

  const goToProfile = () => {
    navigate('/profile')
  }

  const isActive = (path) => location.pathname === path ? 'nav-item active' : 'nav-item'

  return (
    <div className="header">
      <div className="header-left">
        <span className="brand-text" onClick={() => navigate('/')} style={{ cursor: 'pointer' }}>Traffic Detection</span>
        <div className="divider"></div>
        <Link to="/" className={isActive('/')}>首页</Link>
        <Link to="/detection" className={isActive('/detection')}>检测</Link>
        <Link to="/history" className={isActive('/history')}>历史记录</Link>
        {user?.role === 'admin' && (
          <Link to="/analysis" className={isActive('/analysis')}>抓包协议分析</Link>
        )}
        {user?.role === 'admin' && (
          <Link to="/admin/users" className={isActive('/admin/users')}>用户管理</Link>
        )}
      </div>
      
      <div className="header-right">
        {user && (
          <div className="user-info">
            <span className="username">{user.username}</span>
            <span className="role-badge">{user.role === 'admin' ? '管理员' : '用户'}</span>
          </div>
        )}
        <div className="divider"></div>
        <div className="avatar-wrapper" onClick={goToProfile} title="点击进入个人中心">
          <div className="avatar-circle">
            <span className="avatar-text">{user?.username?.charAt(0).toUpperCase() || '?'}</span>
          </div>
        </div>
        <button className="logout-btn" onClick={handleLogout} title="退出登录">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
        </button>
      </div>
    </div>
  )
}
