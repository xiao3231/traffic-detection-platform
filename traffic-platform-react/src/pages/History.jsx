import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'
import './History.css'

const PROTOCOL_ORDER = ['TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'Other']

function protocolIconName(key) {
  if (key === 'TCP') return 'tcp'
  if (key === 'UDP') return 'udp'
  if (key === 'HTTP') return 'http'
  return 'barChart'
}

export default function History() {
  const navigate = useNavigate()
  const [ready, setReady] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const [items, setItems] = useState([])
  const [summary, setSummary] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const sessionRes = await fetch(apiUrl('/api/check-session'), { credentials: 'include' })
        const sessionData = await readJsonResponse(sessionRes)
        if (!sessionData.logged_in) {
          navigate('/login')
          if (!cancelled) setReady(true)
          return
        }
        const res = await fetch(apiUrl('/api/detection-history'), { credentials: 'include' })
        if (res.status === 401) {
          navigate('/login')
          if (!cancelled) setReady(true)
          return
        }
        const body = await readJsonResponse(res)
        if (!res.ok) throw new Error(body.error || '加载失败')
        if (!cancelled) {
          setItems(body.items || [])
          setSummary(body.summary || null)
          setLoadError(null)
        }
      } catch (e) {
        if (!cancelled) setLoadError(e.message || '网络错误')
      } finally {
        if (!cancelled) setReady(true)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [navigate])

  const protocolMax = useMemo(() => {
    if (!summary?.protocols_total) return 0
    return Math.max(
      ...PROTOCOL_ORDER.map((k) => Number(summary.protocols_total[k] || 0)),
      1
    )
  }, [summary])

  if (!ready) {
    return (
      <div className="history-page">
        <Header />
        <main className="history-main history-center">
          <Icon name="loading" size={40} className="spinning" />
        </main>
      </div>
    )
  }

  const total = summary?.total ?? 0
  const safe = summary?.safe ?? 0
  const danger = summary?.danger ?? 0
  const safePct = total > 0 ? Math.round((safe / total) * 1000) / 10 : 0
  const dangerPct = total > 0 ? Math.round((danger / total) * 1000) / 10 : 0

  return (
    <div className="history-page">
      <Header />
      <main className="history-main">
        <header className="history-page-head">
          <h1>检测历史</h1>
          <p className="history-page-desc">
            汇总当前账号在平台上的检测记录、安全 / 危险占比与协议累计分布；数据来自服务端持久化存储。
          </p>
        </header>

        {loadError && (
          <div className="history-banner error">
            <Icon name="error" size={20} />
            <span>{loadError}</span>
          </div>
        )}

        {total === 0 && !loadError ? (
          <div className="history-empty">
            <Icon name="info" size={56} />
            <p>暂无检测记录</p>
            <button type="button" className="history-cta" onClick={() => navigate('/detection')}>
              去检测
            </button>
          </div>
        ) : (
          <>
            <div className="stats-row">
              <div className="stat-card">
                <Icon name="history" size={32} className="stat-icon" />
                <div className="stat-info">
                  <span className="stat-value">{total}</span>
                  <span className="stat-label">检测次数</span>
                </div>
              </div>
              <div className="stat-card">
                <Icon name="safe" size={32} className="stat-icon safe" />
                <div className="stat-info">
                  <span className="stat-value">{safe}</span>
                  <span className="stat-label">安全</span>
                </div>
              </div>
              <div className="stat-card">
                <Icon name="danger" size={32} className="stat-icon danger" />
                <div className="stat-info">
                  <span className="stat-value">{danger}</span>
                  <span className="stat-label">危险</span>
                </div>
              </div>
              <div className="stat-card">
                <Icon name="file" size={32} className="stat-icon" />
                <div className="stat-info">
                  <span className="stat-value">
                    {(summary?.total_packets_sum ?? 0).toLocaleString()}
                  </span>
                  <span className="stat-label">累计数据包</span>
                </div>
              </div>
              <div className="stat-card">
                <Icon name="scan" size={32} className="stat-icon" />
                <div className="stat-info">
                  <span className="stat-value">{summary?.avg_elapsed ?? 0}s</span>
                  <span className="stat-label">平均耗时</span>
                </div>
              </div>
            </div>

            <div className="charts-row">
              <section className="panel">
                <h2 className="panel-head">
                  <Icon name="pieChart" size={22} />
                  安全 / 危险 占比
                </h2>
                <div className="ratio-body">
                  <div
                    className="ratio-donut"
                    style={{
                      background:
                        total === 0
                          ? '#333'
                          : `conic-gradient(#34C759 0% ${safePct}%, #FF3B30 ${safePct}% 100%)`,
                    }}
                  >
                    <div className="ratio-donut-hole">
                      <span className="ratio-donut-pct">{total ? `${safePct}%` : '—'}</span>
                      <span className="ratio-donut-sub">安全</span>
                    </div>
                  </div>
                  <ul className="ratio-legend">
                    <li>
                      <span className="dot safe" />
                      安全 {safe}（{safePct}%）
                    </li>
                    <li>
                      <span className="dot danger" />
                      危险 {danger}（{dangerPct}%）
                    </li>
                  </ul>
                </div>
              </section>

              <section className="panel panel-grow">
                <h2 className="panel-head">
                  <Icon name="barChart" size={22} />
                  协议累计分布（全历史）
                </h2>
                <div className="protocol-stats">
                  {PROTOCOL_ORDER.map((key) => {
                    const n = Number(summary?.protocols_total?.[key] || 0)
                    if (n <= 0) return null
                    const w = Math.max(4, (n / protocolMax) * 100)
                    return (
                      <div key={key} className="protocol-item">
                        <span className="protocol-label">
                          <Icon name={protocolIconName(key)} size={18} />
                          {key}
                        </span>
                        <div className="protocol-bar">
                          <div className="protocol-fill" style={{ width: `${w}%` }} />
                        </div>
                        <span className="protocol-num">{n.toLocaleString()}</span>
                      </div>
                    )
                  })}
                  {PROTOCOL_ORDER.every((key) => !Number(summary?.protocols_total?.[key])) && (
                    <p className="muted">暂无协议累计数据</p>
                  )}
                </div>
              </section>
            </div>

            <section className="panel table-panel">
              <h2 className="panel-head">
                <Icon name="history" size={22} />
                检测明细
              </h2>
              <div className="table-wrap">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>文件名</th>
                      <th>结果</th>
                      <th>数据包</th>
                      <th>耗时</th>
                      <th>时间</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((row) => (
                      <tr key={row.id}>
                        <td>
                          <span className="cell-file">
                            <Icon name="filePcap" size={20} />
                            {row.filename}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${row.safe ? 'safe' : 'danger'}`}>
                            {row.result}
                          </span>
                        </td>
                        <td>{Number(row.total_packets || 0).toLocaleString()}</td>
                        <td>{row.elapsed_time}s</td>
                        <td className="muted">
                          {row.created_at
                            ? new Date(row.created_at).toLocaleString('zh-CN')
                            : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="history-table-footer-hint">共 {items.length} 条记录</p>
            </section>
          </>
        )}
      </main>
    </div>
  )
}
