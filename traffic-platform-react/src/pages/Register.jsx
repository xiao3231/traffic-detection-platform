import { useState } from 'react'
import axios from 'axios'
import { useNavigate, Link } from 'react-router-dom'
import { apiUrl } from '../api'
import './Login.css'

// 配置 axios 允许携带 cookie
axios.defaults.withCredentials = true

export default function Register() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    if (password !== confirmPassword) {
      setError('两次输入的密码不一致')
      return
    }
    
    setLoading(true)
    try {
      await axios.post(apiUrl('/api/register'), {
        username,
        password,
        confirm_password: confirmPassword
      }, {
        withCredentials: true
      })
      alert('注册成功！请登录')
      navigate('/login')
    } catch (err) {
      setError(err.response?.data?.error || '注册失败')
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
            <div className="logo-icon">📝</div>
            <h1>用户注册</h1>
            <p>Create Account</p>
          </div>
          
          <form onSubmit={handleSubmit}>
            {error && <div className="error-message">{error}</div>}
            
            <div className="input-group">
              <div className="input-icon">👤</div>
              <input
                type="text"
                placeholder="用户名 (3-10个字符)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            
            <div className="input-group">
              <div className="input-icon">🔒</div>
              <input
                type="password"
                placeholder="密码 (6-16个字符)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <div className="input-group">
              <div className="input-icon">🔐</div>
              <input
                type="password"
                placeholder="确认密码"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>
            
            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? '注册中...' : '注 册'}
            </button>
          </form>
          
          <div className="register-link">
            <span>已有账号？</span>
            <Link to="/login">立即登录</Link>
          </div>
        </div>
      </div>
    </div>
  )
}
