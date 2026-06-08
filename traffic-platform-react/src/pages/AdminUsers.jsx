import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'
import './AdminUsers.css'

function PasswordInput({ label, value, onChange, placeholder, autoComplete = 'new-password' }) {
  const [visible, setVisible] = useState(false)
  return (
    <label className="adm-field-label">
      {label}
      <div className="adm-password-wrap">
        <input
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
        />
        <button
          type="button"
          className="adm-password-toggle"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? '隐藏密码' : '显示密码'}
          title={visible ? '隐藏密码' : '显示密码'}
        >
          {visible ? (
            <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
              <path
                fill="currentColor"
                d="M12 6.5c3.86 0 7.06 2.51 8.24 6-1.18 3.49-4.38 6-8.24 6s-7.06-2.51-8.24-6C4.94 9.01 8.14 6.5 12 6.5m0-2C6.76 4.5 2.5 7.86 1 12c1.5 4.14 5.76 7.5 11 7.5s9.5-3.36 11-7.5C21.5 7.86 17.24 4.5 12 4.5zm0 5a2.5 2.5 0 0 1 0 5 2.5 2.5 0 0 1 0-5z"
              />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
              <path
                fill="currentColor"
                d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5C21.27 7.61 17 4.5 12 4.5zm0 12.5c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"
              />
            </svg>
          )}
        </button>
      </div>
    </label>
  )
}

export default function AdminUsers() {
  const navigate = useNavigate()
  const [gateOk, setGateOk] = useState(false)
  const [myUserId, setMyUserId] = useState(null)
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [qCommitted, setQCommitted] = useState('')
  const [qInput, setQInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [passwordUser, setPasswordUser] = useState(null)
  const [newPassword, setNewPassword] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [createUsername, setCreateUsername] = useState('')
  const [createPassword, setCreatePassword] = useState('')
  const [createConfirm, setCreateConfirm] = useState('')
  const [createRole, setCreateRole] = useState('user')
  const [createLoading, setCreateLoading] = useState(false)
  const debounceRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const res = await fetch(apiUrl('/api/check-session'), { credentials: 'include' })
      const data = await readJsonResponse(res)
      if (cancelled) return
      if (!data.logged_in || data.role !== 'admin') {
        navigate('/', { replace: true })
        return
      }
      setMyUserId(data.user_id || null)
      setGateOk(true)
    })()
    return () => {
      cancelled = true
    }
  }, [navigate])

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams()
      if (qCommitted.trim()) params.set('q', qCommitted.trim())
      params.set('limit', '80')
      const res = await fetch(apiUrl(`/api/admin/users?${params}`), { credentials: 'include' })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '加载失败')
      setItems(data.items || [])
      setTotal(data.total ?? 0)
    } catch (e) {
      setError(e.message || '网络错误')
    } finally {
      setLoading(false)
    }
  }, [qCommitted])

  useEffect(() => {
    if (!gateOk) return
    load()
  }, [gateOk, load])

  useEffect(() => {
    if (!gateOk) return
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => setQCommitted(qInput), 320)
    return () => clearTimeout(debounceRef.current)
  }, [qInput, gateOk])

  const patchUser = async (userId, body) => {
    const res = await fetch(apiUrl(`/api/admin/users/${userId}`), {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await readJsonResponse(res)
    if (!res.ok) throw new Error(data.error || '操作失败')
    await load()
  }

  const savePassword = async () => {
    if (!passwordUser || !newPassword) return
    try {
      await patchUser(passwordUser.id, { password: newPassword })
      setPasswordUser(null)
      setNewPassword('')
    } catch (e) {
      setError(e.message)
    }
  }

  const unblock = async (u) => {
    if (!window.confirm(`将用户「${u.username}」解封为正常状态？`)) return
    try {
      await patchUser(u.id, { status: 'active' })
    } catch (e) {
      setError(e.message)
    }
  }

  const block = async (u) => {
    if (!window.confirm(`封禁用户「${u.username}」？对方将无法登录。`)) return
    try {
      await patchUser(u.id, { status: 'blocked' })
    } catch (e) {
      setError(e.message)
    }
  }

  const createUser = async () => {
    setCreateLoading(true)
    setError(null)
    try {
      const res = await fetch(apiUrl('/api/admin/users'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: createUsername.trim(),
          password: createPassword,
          confirm_password: createConfirm,
          role: createRole,
        }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '创建失败')
      setShowCreate(false)
      setCreateUsername('')
      setCreatePassword('')
      setCreateConfirm('')
      setCreateRole('user')
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setCreateLoading(false)
    }
  }

  if (!gateOk) {
    return (
      <div className="adm-page">
        <Header />
        <main className="adm-main adm-center">
          <Icon name="loading" size={40} className="adm-spin" />
        </main>
      </div>
    )
  }

  return (
    <div className="adm-page">
      <Header />
      <main className="adm-main">
        <section className="adm-headline">
          <div className="adm-headline-bg" aria-hidden />
          <div className="adm-headline-inner">
            <h1>用户管理</h1>
            <p>创建用户、搜索账号、查看检测统计，重置密码或封禁 / 解封。</p>
          </div>
        </section>

        <div className="adm-toolbar">
          <div className="adm-search-wrap">
            <Icon name="user" size={20} />
            <input
              type="search"
              placeholder="按用户名搜索…"
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              aria-label="搜索用户"
            />
          </div>
          <span className="adm-count">
            {loading ? '加载中…' : `共 ${total} 个账号`}
          </span>
          <button type="button" className="adm-btn primary" onClick={() => setShowCreate(true)}>
            创建用户
          </button>
        </div>

        {error && (
          <div className="adm-banner-err">
            <Icon name="error" size={18} />
            <span>{error}</span>
          </div>
        )}

        <div className="adm-user-list">
          {items.map((u) => (
            <article key={u.id} className="adm-user-card">
              <div className="adm-avatar" aria-hidden>
                {(u.username || '?').charAt(0).toUpperCase()}
              </div>
              <div className="adm-user-main">
                <div className="adm-user-name">{u.username}</div>
                <div className="adm-user-meta">
                  <span className={`adm-pill role-${u.role === 'admin' ? 'admin' : 'user'}`}>
                    {u.role === 'admin' ? '管理员' : '普通用户'}
                  </span>
                  <span className={`adm-pill ${u.status === 'blocked' ? 'blocked' : 'ok'}`}>
                    {u.status === 'blocked' ? '已封禁' : '正常'}
                  </span>
                  <span className="adm-pill">检测提交 {u.detection_submit_count ?? 0} 次</span>
                  <span className="adm-pill">不同 pcap 名 {u.detection_distinct_pcap ?? 0} 个</span>
                </div>
              </div>
              <div className="adm-actions">
                <button type="button" className="adm-btn primary" onClick={() => setPasswordUser(u)}>
                  修改密码
                </button>
                {u.status === 'blocked' ? (
                  <button type="button" className="adm-btn" onClick={() => unblock(u)}>
                    解封
                  </button>
                ) : (
                  <button
                    type="button"
                    className="adm-btn danger"
                    onClick={() => block(u)}
                    disabled={myUserId != null && u.id === myUserId}
                    title={myUserId != null && u.id === myUserId ? '不能封禁当前登录账号' : ''}
                  >
                    封禁
                  </button>
                )}
              </div>
            </article>
          ))}
        </div>

        {showCreate && (
          <div
            className="adm-modal-overlay"
            role="presentation"
            onClick={(e) => e.target === e.currentTarget && !createLoading && setShowCreate(false)}
          >
            <div className="adm-modal" role="dialog" aria-labelledby="adm-create-title">
              <h3 id="adm-create-title">创建用户</h3>
              <p className="sub">由管理员新建账号，操作将记入审计日志。</p>
              <label className="adm-field-label">
                用户名（3–10 位）
                <input
                  type="text"
                  value={createUsername}
                  onChange={(e) => setCreateUsername(e.target.value)}
                  placeholder="请输入用户名"
                  autoComplete="off"
                />
              </label>
              <PasswordInput
                label="密码（6–16 位）"
                value={createPassword}
                onChange={(e) => setCreatePassword(e.target.value)}
                placeholder="请输入密码"
              />
              <PasswordInput
                label="确认密码"
                value={createConfirm}
                onChange={(e) => setCreateConfirm(e.target.value)}
                placeholder="再次输入密码"
              />
              <label className="adm-field-label">
                身份
                <select value={createRole} onChange={(e) => setCreateRole(e.target.value)}>
                  <option value="user">普通用户</option>
                  <option value="admin">管理员</option>
                </select>
              </label>
              <div className="adm-modal-actions">
                <button
                  type="button"
                  className="adm-btn"
                  disabled={createLoading}
                  onClick={() => setShowCreate(false)}
                >
                  取消
                </button>
                <button
                  type="button"
                  className="adm-btn primary"
                  disabled={createLoading}
                  onClick={createUser}
                >
                  {createLoading ? '创建中…' : '确认创建'}
                </button>
              </div>
            </div>
          </div>
        )}

        {passwordUser && (
          <div
            className="adm-modal-overlay"
            role="presentation"
            onClick={(e) => e.target === e.currentTarget && setPasswordUser(null)}
          >
            <div className="adm-modal" role="dialog" aria-labelledby="adm-pw-title">
              <h3 id="adm-pw-title">重置密码</h3>
              <p className="sub">用户：{passwordUser.username}</p>
              <input
                type="password"
                placeholder="新密码 6–16 位"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                autoComplete="new-password"
              />
              <div className="adm-modal-actions">
                <button type="button" className="adm-btn" onClick={() => setPasswordUser(null)}>
                  取消
                </button>
                <button type="button" className="adm-btn primary" onClick={savePassword}>
                  保存
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
