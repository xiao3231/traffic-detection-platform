import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'
import './Home.css'

const HOME_SIGNATURE = 'XM 1793143191@qq.com'

const FEATURE_DETECTION = {
  to: '/detection',
  icon: 'scan',
  title: '流量检测',
  desc: '上传 pcap，基于随机森林模型分析恶意倾向，查看协议分布与检测结论。',
  cta: '进入检测',
  cardSize: 'side',
}

const FEATURE_HISTORY = {
  to: '/history',
  icon: 'history',
  title: '历史记录',
  desc: '按时间查看本人检测记录、图表统计与协议占比，便于对比与追溯。',
  cta: '查看历史',
  cardSize: 'side',
}

const FEATURE_ANALYSIS = {
  to: '/analysis',
  icon: 'barChart',
  title: '抓包协议分析',
  desc: '实时或离线抓包、会话标注与特征预览；支持模型重训、指标对比与版本恢复，管理员工作台核心入口。',
  cta: '打开分析',
  cardSize: 'hero',
}

const FEATURE_ADMIN_USERS = {
  to: '/admin/users',
  icon: 'settings',
  title: '用户管理',
  desc: '搜索用户、重置密码、查看检测提交与不重复 pcap 数量、封禁或解封账号。',
  cta: '用户管理',
  cardSize: 'wide',
}

const FEATURE_PROFILE = {
  to: '/profile',
  icon: 'userCircle',
  title: '个人中心',
  desc: '账号与偏好入口，与顶栏头像一致，可在此扩展资料与设置。',
  cta: '个人中心',
  cardSize: 'compact',
}

function homeFeatureCards(isAdmin) {
  if (isAdmin) {
    return [
      FEATURE_ANALYSIS,
      FEATURE_HISTORY,
      FEATURE_DETECTION,
      FEATURE_ADMIN_USERS,
      FEATURE_PROFILE,
    ]
  }
  return [
    { ...FEATURE_DETECTION, cardSize: 'hero' },
    FEATURE_HISTORY,
    FEATURE_PROFILE,
  ]
}

const HERO_ICON = 34
const SIDE_ICON = 26
const WIDE_ICON = 28
const COMPACT_ICON = 24

function cardIconSize(cardSize) {
  if (cardSize === 'hero') return HERO_ICON
  if (cardSize === 'wide') return WIDE_ICON
  if (cardSize === 'compact') return COMPACT_ICON
  return SIDE_ICON
}

/**卡片布局 */
function HomeFeatureBento({ isAdmin }) {
  const cards = homeFeatureCards(isAdmin)
  const bentoMod = cards.length === 5 ? 'home-cards--bento-5' : 'home-cards--bento-3'

  return (
    <div className={`home-cards ${bentoMod}`}>
      {cards.map((f) => (
        <Link
          key={f.to}
          to={f.to}
          className={`home-card home-card--${f.cardSize}`}
        >
          <div className="home-card-icon">
            <Icon name={f.icon} size={cardIconSize(f.cardSize)} />
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
  )
}

/** 首页技术条：与本平台训练 / 检测链路一致 */
const MARQUEE_TECH_STACK = [
  { label: 'Scapy', sub: 'pcap 解析与抓包', icon: 'scan' },
  { label: '随机森林', sub: '主检测模型', icon: 'barChart' },
  { label: 'scikit-learn', sub: '训练与基线对比', icon: 'chart' },
  { label: '17 维流特征', sub: '统计 + 协议 + 行为', icon: 'file' },
  { label: 'joblib', sub: 'model.pkl 持久化', icon: 'folder' },
  { label: 'Flask API', sub: '检测 / 重训接口', icon: 'settings' },
  { label: 'MongoDB', sub: '检测与训练记录', icon: 'history' },
  { label: 'F1 · 混淆矩阵', sub: '恶意类网安指标', icon: 'pieChart' },
  { label: 'React + Vite', sub: '检测工作台前端', icon: 'home' },
  { label: 'PCAP 流水线', sub: '上传 → 特征 → 判别', icon: 'filePcap' },
]

/** 技术条显示 */
function TechMarquee() {
  const chip = (item, key) => (
    <span key={key} className="home-chip">
      <Icon name={item.icon} size={18} />
      <span className="home-chip-text">
        <span className="home-chip-label">{item.label}</span>
        {item.sub ? <span className="home-chip-sub">{item.sub}</span> : null}
      </span>
    </span>
  )

  return (
    <div className="home-marquee-wrap" aria-label="平台技术栈">
      <div className="home-marquee-track">
        <div className="home-marquee-group">
          {MARQUEE_TECH_STACK.map((item) => chip(item, item.label))}
        </div>
        <div className="home-marquee-group" aria-hidden="true">
          {MARQUEE_TECH_STACK.map((item) => chip(item, `dup-${item.label}`))}
        </div>
      </div>
    </div>
  )
}

function formatClock(d) {
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

  /** 默认导出组件 */
export default function Home() {
  const [loggedIn, setLoggedIn] = useState(false)
  const [role, setRole] = useState(null)
  const [clock, setClock] = useState(() => formatClock(new Date()))
  const [apiOk, setApiOk] = useState(null)

  /** 定时更新时间 */
  useEffect(() => {
    const t = setInterval(() => setClock(formatClock(new Date())), 1000)
    return () => clearInterval(t)
  }, [])

  /** 获取会话信息 */
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

  /** 检测后端连接状态 */
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
            你好！{role === 'admin' ? '管理员' : '用户'}！
            <br />
            基于 Scapy 与机器学习的一站式平台：检测、历史归档{role === 'admin' ? '、抓包与模型训练' : ''}
            。从下方卡片进入各模块。
          </p>
          <div className="home-live-row">
            <span>
              本地时间 <span className="mono">{clock}</span>
            </span>
          </div>

          <TechMarquee />
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

        <HomeFeatureBento isAdmin={role === 'admin'} />
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
