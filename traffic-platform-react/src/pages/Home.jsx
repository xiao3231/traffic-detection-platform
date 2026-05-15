import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'
import './Home.css'

/** 首页底部署名：改成你的名字或团队名即可 */
const HOME_SIGNATURE = 'Neptune'

const FEATURE_DETECTION = {
  to: '/detection',
  icon: 'scan',
  title: '流量检测',
  desc: '上传 pcap，基于随机森林模型分析恶意倾向，查看协议分布与检测结论。',
  cta: '进入检测',
}

const FEATURE_HISTORY = {
  to: '/history',
  icon: 'history',
  title: '历史记录',
  desc: '按时间查看本人检测记录、图表统计与协议占比，便于对比与追溯。',
  cta: '查看历史',
}

const FEATURE_ANALYSIS = {
  to: '/analysis',
  icon: 'barChart',
  title: '抓包协议分析',
  desc: '实时或离线抓包、会话标注、特征预览与模型重训、版本恢复（仅管理员）。',
  cta: '打开分析',
}

const FEATURE_ADMIN_USERS = {
  to: '/admin/users',
  icon: 'settings',
  title: '用户管理',
  desc: '搜索用户、重置密码、查看检测提交与不重复 pcap 数量、封禁或解封账号。',
  cta: '用户管理',
}

const FEATURE_PROFILE = {
  to: '/profile',
  icon: 'userCircle',
  title: '个人中心',
  desc: '账号与偏好入口，与顶栏头像一致，可在此扩展资料与设置。',
  cta: '个人中心',
}

function homeFeatureCards(isAdmin) {
  const list = [FEATURE_DETECTION, FEATURE_HISTORY]
  if (isAdmin) {
    list.push(FEATURE_ANALYSIS, FEATURE_ADMIN_USERS)
  }
  list.push(FEATURE_PROFILE)
  return list
}

const MARQUEE_PROTOCOLS = [
  { label: 'TCP', icon: 'tcp' },
  { label: 'UDP', icon: 'udp' },
  { label: 'HTTP', icon: 'http' },
  { label: 'HTTPS', icon: 'https' },
  { label: 'PCAP', icon: 'filePcap' },
  { label: 'Scapy', icon: 'shield' },
]

function formatClock(d) {
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export default function Home() {
  const [loggedIn, setLoggedIn] = useState(false)
  const [role, setRole] = useState(null)
  const [clock, setClock] = useState(() => formatClock(new Date()))
  const [apiOk, setApiOk] = useState(null)

  useEffect(() => {
    const t = setInterval(() => setClock(formatClock(new Date())), 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    let cancelled = false
    fetch(apiUrl('/api/check-session'), { credentials: 'include' })
      .then((res) => readJsonResponse(res))
      .then((data) => {
        if (!cancelled) {
          setLoggedIn(!!data.logged_in)
          setRole(data.logged_in ? data.role || 'user' : null)
        }
      })
      .catch(() => {
        if (!cancelled) setLoggedIn(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    const ping = () => {
      fetch(apiUrl('/api/status'))
        .then((r) => {
          if (!cancelled) setApiOk(r.ok)
        })
        .catch(() => {
          if (!cancelled) setApiOk(false)
        })
    }
    ping()
    const id = setInterval(ping, 12000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const duplexMarquee = [...MARQUEE_PROTOCOLS, ...MARQUEE_PROTOCOLS]

  return (
    <div className="home-dashboard">
      <div className="home-bg" aria-hidden="true">
        <div className="glow-orb" />
        <div className="glow-orb secondary" />
        {Array.from({ length: 12 }, (_, i) => (
          <div key={i} className="particle" />
        ))}
        <div className="grid-lines" />
      </div>

      <Header />

      <main className="home-main">
        <section className="home-hero">
          <div className="home-hero-badge">
            <span className={`dot ${apiOk === false ? 'warn' : ''}`} />
            {apiOk === null ? '服务检测中…' : apiOk ? '后端在线' : '后端暂不可达'}
          </div>
          <h1>恶意流量检测工作台</h1>
          <p className="home-hero-sub">
            基于 Scapy 与机器学习的一站式平台：检测、历史归档{role === 'admin' ? '、抓包与模型训练（管理员）' : ''}
            。从下方卡片进入各模块。
          </p>
          <div className="home-live-row">
            <span>
              本地时间 <span className="mono">{clock}</span>
            </span>
            <span className="sep">|</span>
            <span>背景粒子与网格持续运动</span>
          </div>

          <div className="home-marquee-wrap">
            <div className="home-marquee">
              {duplexMarquee.map((item, idx) => (
                <span key={`${item.label}-${idx}`} className="home-chip">
                  <Icon name={item.icon} size={18} />
                  {item.label}
                </span>
              ))}
            </div>
          </div>
        </section>

        {!loggedIn && (
          <div className="home-guest">
            未登录时也可浏览首页；使用检测与历史请先
            <Link to="/login">登录</Link>
            或
            <Link to="/register">注册</Link>
            （抓包协议分析仅管理员可见）。
          </div>
        )}

        <div className="home-cards">
          {homeFeatureCards(role === 'admin').map((f) => (
            <Link key={f.to} to={f.to} className="home-card">
              <div className="home-card-icon">
                <Icon name={f.icon} size={28} />
              </div>
              <h2>{f.title}</h2>
              <p>{f.desc}</p>
              <span className="home-card-cta">
                {f.cta}
                <span aria-hidden="true">→</span>
              </span>
            </Link>
          ))}
        </div>
      </main>

      <footer className="home-footer">
        <div className="home-footer-inner">
          <p className="sig">
            <strong>{HOME_SIGNATURE}</strong>
            {' · '}
            {new Date().getFullYear()}
            {' · '}
            Traffic Detection Platform
          </p>
        </div>
      </footer>
    </div>
  )
}
