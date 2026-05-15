import { useState } from 'react'
import axios from 'axios'
import { useNavigate, Link } from 'react-router-dom'
import { apiUrl } from '../api'
import './Login.css'

// 配置 axios 允许携带 cookie
axios.defaults.withCredentials = true

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await axios.post(apiUrl('/api/login'), {
        username,
        password
      }, {
        withCredentials: true
      })
      navigate('/')
      window.location.reload()
    } catch (err) {
      setError(err.response?.data?.error || '登录失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      {/* 动态粒子背景 */}
      <div className="bg-animation">
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="particle"></div>
        <div className="grid-lines"></div>
      </div>

      <div className="login-container">
        <div className="login-card">
          <div className="logo-section">
            <div className="logo-icon">🛡️</div>
            <h1>流量检测平台</h1>
            <p>Network Traffic Analysis</p>
          </div>
          
          <form onSubmit={handleSubmit}>
            {error && <div className="error-message">{error}</div>}
            
            <div className="input-group">
              <div className="input-icon">👤</div>
              <input
                type="text"
                placeholder="用户名"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            
            <div className="input-group">
              <div className="input-icon">🔒</div>
              <input
                type="password"
                placeholder="密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            
            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? '登录中...' : '登 录'}
            </button>
          </form>
          
          <div className="register-link">
            <span>还没有账号？</span>
            <Link to="/register">立即注册</Link>
          </div>
        </div>
      </div>
    </div>
  )
}
