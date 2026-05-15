import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'
import './AdminUsers.css'

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
            <p>搜索用户、查看检测提交次数与不重复 pcap 名数量，重置密码或调整账号状态（封禁 / 解封）。</p>
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
