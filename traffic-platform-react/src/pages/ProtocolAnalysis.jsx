import { useState, useEffect, useRef, useCallback, Fragment } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'

function TreeNodes({ nodes, depth = 0 }) {
  if (!nodes?.length) return null
  return (
    <ul className={`dissect-list depth-${depth}`}>
      {nodes.map((node, i) => (
        <li key={`${depth}-${i}`}>
          <span className="dissect-line">{node.text}</span>
          {node.children?.length > 0 && <TreeNodes nodes={node.children} depth={depth + 1} />}
        </li>
      ))}
    </ul>
  )
}

function ChecksumBox({ checksums }) {
  return (
    <div className="checksum-box">
      <strong>校验和</strong>
      {checksums.ip && <span>IP: {checksums.ip}</span>}
      {checksums.tcp && <span>TCP: {checksums.tcp}</span>}
      {checksums.udp && <span>UDP: {checksums.udp}</span>}
      {checksums.icmp && <span>ICMP: {checksums.icmp}</span>}
    </div>
  )
}

export default function ProtocolAnalysis() {
  const navigate = useNavigate()
  const fileRef = useRef(null)
  const listRef = useRef(null)

  const [ready, setReady] = useState(false)
  const [bpf, setBpf] = useState('')
  const [running, setRunning] = useState(false)
  const [paused, setPaused] = useState(false)
  const [packetCount, setPacketCount] = useState(0)
  const [packets, setPackets] = useState([])
  const [selectedIndex, setSelectedIndex] = useState(null)
  const [detail, setDetail] = useState(null)
  const [sessions, setSessions] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [featurePreview, setFeaturePreview] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewSessionId, setPreviewSessionId] = useState('')
  const [modelRuns, setModelRuns] = useState([])
  const [trainLoading, setTrainLoading] = useState(false)
  const [restoreRunId, setRestoreRunId] = useState(null)
  const [includeLabeledInTrain, setIncludeLabeledInTrain] = useState(true)
  const [sniffError, setSniffError] = useState('')
  const [featureSchema, setFeatureSchema] = useState(null)
  const [lastTrainMetrics, setLastTrainMetrics] = useState(null)
  const [expandedRunId, setExpandedRunId] = useState(null)

  const loadSessions = useCallback(async () => {
    const res = await fetch(apiUrl('/api/capture/sessions'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setSessions(data.items || [])
  }, [])

  const loadModelRuns = useCallback(async () => {
    const res = await fetch(apiUrl('/api/train/runs'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setModelRuns(data.items || [])
  }, [])

  const loadFeatureSchema = useCallback(async () => {
    const res = await fetch(apiUrl('/api/train/feature-schema'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setFeatureSchema(data)
  }, [])

  const refreshStatus = useCallback(async () => {
    const res = await fetch(apiUrl('/api/capture/status'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) {
      setRunning(!!data.running)
      setPaused(!!data.paused)
      setPacketCount(data.packet_count || 0)
      if (data.last_error) setSniffError(data.last_error)
    }
    return data
  }, [])

  const loadDetail = useCallback(async (index) => {
    const res = await fetch(apiUrl(`/api/capture/packet/${index}`), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setDetail(data)
  }, [])

  /** 开发环境下 Vite 代理会缓冲 SSE，改用轮询拉包更可靠 */
  useEffect(() => {
    if (!running || paused) return undefined

    const tick = async () => {
      try {
        const res = await fetch(apiUrl('/api/capture/pending'), { credentials: 'include' })
        const data = await readJsonResponse(res)
        if (data.status) {
          setRunning(!!data.status.running)
          setPaused(!!data.status.paused)
          setPacketCount(data.status.packet_count ?? 0)
          if (data.status.last_error) setSniffError(data.status.last_error)
        }
        if (data.packets?.length) {
          setPackets((prev) => {
            const next = [...prev, ...data.packets]
            if (listRef.current) {
              requestAnimationFrame(() => {
                listRef.current.scrollTop = listRef.current.scrollHeight
              })
            }
            return next
          })
        }
      } catch {
        /* 轮询偶发失败忽略 */
      }
    }

    tick()
    const id = setInterval(tick, 300)
    return () => clearInterval(id)
  }, [running, paused])

  /** 抓包线程结束时可能仍有一批包在 pending，再拉一次避免列表缺尾包 */
  useEffect(() => {
    if (running) return undefined
    let cancelled = false
    const drain = async () => {
      try {
        const res = await fetch(apiUrl('/api/capture/pending'), { credentials: 'include' })
        const data = await readJsonResponse(res)
        if (cancelled || !data.packets?.length) return
        setPackets((prev) => [...prev, ...data.packets])
        if (data.status?.packet_count != null) setPacketCount(data.status.packet_count)
      } catch {
        /* ignore */
      }
    }
    drain()
    return () => {
      cancelled = true
    }
  }, [running])

  useEffect(() => {
    let cancelled = false
    async function init() {
      try {
        const sessionRes = await fetch(apiUrl('/api/check-session'), { credentials: 'include' })
        const sessionData = await readJsonResponse(sessionRes)
        if (!sessionData.logged_in) {
          navigate('/login')
          return
        }
        if (sessionData.role !== 'admin') {
          navigate('/', { replace: true })
          return
        }
        const st = await refreshStatus()
        await loadSessions()
        await loadModelRuns()
        await loadFeatureSchema()
        if (!cancelled && st?.running) {
          /* 轮询由 useEffect([running,paused]) 自动启动 */
        }
      } catch (e) {
        if (!cancelled) setError(e.message || '加载失败')
      } finally {
        if (!cancelled) setReady(true)
      }
    }
    init()
    return () => {
      cancelled = true
    }
  }, [navigate, refreshStatus, loadSessions, loadModelRuns, loadFeatureSchema])

  const postAction = async (path, body) => {
    setBusy(true)
    setError(null)
    try {
      const res = await fetch(apiUrl(path), {
        method: 'POST',
        credentials: 'include',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '操作失败')
      return data
    } finally {
      setBusy(false)
    }
  }

  const handleStart = async () => {
    setPackets([])
    setSelectedIndex(null)
    setDetail(null)
    setSniffError('')
    await postAction('/api/capture/start', { bpf_filter: bpf })
    await refreshStatus()
  }

  const handlePauseToggle = async () => {
    if (paused) await postAction('/api/capture/resume')
    else await postAction('/api/capture/pause')
    await refreshStatus()
  }

  const handleStop = async () => {
    const data = await postAction('/api/capture/stop')
    setRunning(false)
    setPaused(false)
    if (data.session) await loadSessions()
    await refreshStatus()
  }

  const handleClear = async () => {
    await postAction('/api/capture/clear')
    setPackets([])
    setSelectedIndex(null)
    setDetail(null)
    setPacketCount(0)
    setSniffError('')
    await refreshStatus()
  }

  const handleFeaturePreview = async (useSession) => {
    setPreviewLoading(true)
    setError(null)
    try {
      const body = useSession && previewSessionId ? { session_id: previewSessionId } : {}
      const res = await fetch(apiUrl('/api/capture/features-preview'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '特征预览失败')
      setFeaturePreview(data)
    } catch (e) {
      setError(e.message)
      setFeaturePreview(null)
    } finally {
      setPreviewLoading(false)
    }
  }

  const handleAnnotate = async (sessionId, annotation) => {
    try {
      const res = await fetch(apiUrl(`/api/capture/sessions/${sessionId}/annotate`), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ annotation }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '标注失败')
      await loadSessions()
    } catch (e) {
      setError(e.message)
    }
  }

  const handleTrainRebuild = async () => {
    setTrainLoading(true)
    setError(null)
    try {
      const res = await fetch(apiUrl('/api/train/rebuild'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ include_labeled_captures: includeLabeledInTrain }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '训练失败')
      await loadModelRuns()
      if (data.metrics) setLastTrainMetrics(data.metrics)
      const m = data.metrics || {}
      alert(
        `训练完成（${m.feature_count ?? '—'} 维特征）\n` +
          `测试准确率: ${m.test_score != null ? (m.test_score * 100).toFixed(2) : '—'}%\n` +
          `恶意类 Recall: ${m.malicious_recall != null ? (m.malicious_recall * 100).toFixed(2) : '—'}%  F1: ${m.malicious_f1 != null ? (m.malicious_f1 * 100).toFixed(2) : '—'}%\n` +
          `合并正常 pcap: ${data.merged_good_pcaps}，恶意: ${data.merged_bad_pcaps}\n` +
          '详见下方「本次训练评估」与训练记录。'
      )
    } catch (e) {
      setError(e.message)
    } finally {
      setTrainLoading(false)
    }
  }

  const handleRestoreModelRun = async (runId) => {
    if (
      !window.confirm(
        '确定将线上检测使用的 model.pkl 恢复为该次训练保存的版本？当前磁盘上的 model.pkl 将被覆盖。'
      )
    ) {
      return
    }
    setRestoreRunId(runId)
    setError(null)
    try {
      const res = await fetch(apiUrl('/api/train/restore'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: runId }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '恢复失败')
      await loadModelRuns()
      alert(data.message || '已恢复')
    } catch (e) {
      setError(e.message)
    } finally {
      setRestoreRunId(null)
    }
  }

  const handleOpenPcap = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      const form = new FormData()
      form.append('file', file)
      form.append('bpf_filter', bpf)
      const res = await fetch(apiUrl('/api/capture/open-pcap'), {
        method: 'POST',
        credentials: 'include',
        body: form,
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '打开失败')
      setPackets([])
      setSelectedIndex(null)
      setDetail(null)
      setSniffError('')
      await refreshStatus()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
      e.target.value = ''
    }
  }

  if (!ready) {
    return (
      <div className="pa-page">
        <Header />
        <main className="pa-main pa-center">
          <Icon name="loading" size={40} className="spinning" />
        </main>
        <style>{pageStyles}</style>
      </div>
    )
  }

  return (
    <div className="pa-page">
      <Header />
      <main className="pa-main">
        <header className="pa-page-head">
          <h1>抓包协议分析</h1>
          <p>实时抓包 / 离线 pcap · 协议解析 · 特征与模型预览 · 会话标注 · 合并重训</p>
        </header>

        {error && (
          <div className="pa-banner">
            <Icon name="error" size={20} />
            <span>{error}</span>
          </div>
        )}

        <div className="pa-toolbar">
          <button type="button" className="pa-btn primary" disabled={running || busy} onClick={handleStart}>
            开始抓包
          </button>
          <button type="button" className="pa-btn" disabled={!running || busy} onClick={handlePauseToggle}>
            {paused ? '继续' : '暂停'}
          </button>
          <button type="button" className="pa-btn" disabled={!running || busy} onClick={handleStop}>
            停止并保存
          </button>
          <button type="button" className="pa-btn" disabled={busy} onClick={handleClear}>
            清空
          </button>
          <button
            type="button"
            className="pa-btn"
            disabled={running || busy}
            onClick={() => fileRef.current?.click()}
          >
            打开 pcap
          </button>
          <input ref={fileRef} type="file" accept=".pcap" hidden onChange={handleOpenPcap} />
          <label className="bpf-label">
            BPF 过滤器
            <input
              className="bpf-input"
              value={bpf}
              onChange={(ev) => setBpf(ev.target.value)}
              placeholder="例如 tcp port 80"
              disabled={running}
            />
          </label>
        </div>

        <div className="pa-stats">
          <span>
            <Icon name="scan" size={18} /> 缓冲包数：{packetCount}
            {packetCount >= 5000 ? '（已达上限 5000）' : ''}
          </span>
          <span>
            <Icon name="info" size={18} /> 状态：{running ? (paused ? '已暂停' : '抓包中') : '空闲'}
          </span>
        </div>
        {sniffError && (
          <div className="pa-sniff-error">
            <Icon name="warning" size={18} />
            <span>抓包异常：{sniffError}（若权限不足请用 sudo 启动后端，或改用「打开 pcap」）</span>
          </div>
        )}
        {running && !paused && packetCount === 0 && !sniffError && (
          <p className="muted hint">正在监听… 若长时间无包，可能当前网卡无流量或需管理员权限。</p>
        )}

        <div className="pa-panels">
          <section className="pa-panel list-panel">
            <h2>
              <Icon name="history" size={20} /> 数据包列表
            </h2>
            <div className="packet-list" ref={listRef}>
              {packets.length === 0 ? (
                <p className="muted">暂无数据包，点击「开始抓包」或「打开 pcap」</p>
              ) : (
                <table className="pa-table compact">
                  <thead>
                    <tr>
                      <th>No.</th>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Proto</th>
                      <th>Len</th>
                      <th>Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packets.map((p) => (
                      <tr
                        key={p.index}
                        className={selectedIndex === p.index ? 'selected' : ''}
                        onClick={() => {
                          setSelectedIndex(p.index)
                          loadDetail(p.index)
                        }}
                      >
                        <td>{p.index}</td>
                        <td>{p.time}</td>
                        <td>{p.src}</td>
                        <td>{p.dst}</td>
                        <td>{p.proto}</td>
                        <td>{p.length}</td>
                        <td className="info-cell">{p.info}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </section>

          <section className="pa-panel dissect-panel">
            <h2>
              <Icon name="tcp" size={20} /> 协议解析
            </h2>
            {detail ? (
              <div className="dissect-wrap">
                <TreeNodes nodes={detail.tree} />
                {detail.checksums && Object.keys(detail.checksums).length > 0 && (
                  <ChecksumBox checksums={detail.checksums} />
                )}
              </div>
            ) : (
              <p className="muted">点击左侧数据包查看分层解析</p>
            )}
          </section>
        </div>

        <section className="pa-panel hex-panel">
          <h2>
            <Icon name="file" size={20} /> Hexdump
          </h2>
          <pre className="hex-pre">{detail?.hexdump || '—'}</pre>
        </section>

        <section className="pa-panel sessions-panel">
          <h2>
            <Icon name="folder" size={20} /> 已保存会话（MongoDB）
          </h2>
          {sessions.length === 0 ? (
            <p className="muted">停止抓包后会自动写入 capture_sessions</p>
          ) : (
            <div className="table-scroll">
              <table className="pa-table">
                <thead>
                  <tr>
                    <th>模式</th>
                    <th>包数</th>
                    <th>BPF</th>
                    <th>文件</th>
                    <th>标注</th>
                    <th>结束时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr key={s.id}>
                      <td>{s.mode === 'live' ? '实时' : '离线'}</td>
                      <td>{s.packet_count}</td>
                      <td>{s.bpf_filter || '—'}</td>
                      <td className="fname-cell">{s.pcap_filename || '—'}</td>
                      <td>
                        {!s.annotation && <span className="pa-tag muted">未标注</span>}
                        {s.annotation === 'normal' && <span className="pa-tag good">正常样本</span>}
                        {s.annotation === 'malicious' && <span className="pa-tag bad">恶意样本</span>}
                      </td>
                      <td className="muted">
                        {s.ended_at ? new Date(s.ended_at).toLocaleString('zh-CN') : '—'}
                      </td>
                      <td className="annotate-cell">
                        <button type="button" className="pa-mini" onClick={() => handleAnnotate(s.id, 'normal')}>
                          标正常
                        </button>
                        <button type="button" className="pa-mini" onClick={() => handleAnnotate(s.id, 'malicious')}>
                          标恶意
                        </button>
                        <button type="button" className="pa-mini" onClick={() => handleAnnotate(s.id, '')}>
                          清除
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="pa-panel feature-panel">
          <h2>
            <Icon name="chart" size={20} /> 特征与模型预览（与检测模型一致）
          </h2>
          <p className="muted small">
            按「流」聚合为 12 维特征；可对<strong>当前缓冲</strong>或<strong>已保存会话</strong>的 pcap 计算，并显示当前 model.pkl 对每条流的预测（1=安全，0=危险）。
          </p>
          <div className="preview-toolbar">
            <button
              type="button"
              className="pa-btn primary"
              disabled={previewLoading || busy}
              onClick={() => handleFeaturePreview(false)}
            >
              {previewLoading ? '计算中…' : '从当前缓冲计算'}
            </button>
            <select
              className="pa-select"
              value={previewSessionId}
              onChange={(e) => setPreviewSessionId(e.target.value)}
            >
              <option value="">选择已保存会话…</option>
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.pcap_filename || s.id}（{s.packet_count} 包）
                </option>
              ))}
            </select>
            <button
              type="button"
              className="pa-btn"
              disabled={previewLoading || !previewSessionId}
              onClick={() => handleFeaturePreview(true)}
            >
              从选中会话计算
            </button>
          </div>
          {featurePreview && (
            <div className="preview-result">
              <p className="preview-summary">
                <Icon name="pieChart" size={18} /> {featurePreview.prediction_summary}
                {featurePreview.truncated ? '（表格仅显示前 80 条流）' : ''}
              </p>
              {featurePreview.flow_count === 0 ? (
                <p className="muted">未形成流级特征，可多抓一些包或换 pcap。</p>
              ) : (
                <div className="table-scroll">
                  <table className="pa-table compact">
                    <thead>
                      <tr>
                        <th>流#</th>
                        <th>模型预测</th>
                        <th>len_mean</th>
                        <th>len_std</th>
                        <th>time_mean</th>
                        <th>time_std</th>
                        <th>…</th>
                      </tr>
                    </thead>
                    <tbody>
                      {featurePreview.flows.map((f) => (
                        <tr key={f.index}>
                          <td>{f.index}</td>
                          <td>
                            <span className={f.prediction === 1 ? 'pa-tag good' : 'pa-tag bad'}>
                              {f.prediction_label}
                            </span>
                          </td>
                          <td>{f.features[0]?.toFixed(2)}</td>
                          <td>{f.features[1]?.toFixed(2)}</td>
                          <td>{f.features[2]?.toFixed(2)}</td>
                          <td>{f.features[3]?.toFixed(2)}</td>
                          <td className="muted">共 {f.features.length} 维</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </section>

        {featureSchema?.feature_names?.length > 0 && (
          <section className="pa-panel schema-panel">
            <h2>
              <Icon name="info" size={20} /> 流级特征说明（网安）
            </h2>
            <p className="muted small">
              共 {featureSchema.feature_names.length} 维；含包长/时序、协议计数及扩展行为特征（包数、小包占比、端口多样性等）。
            </p>
            <div className="pa-schema-list">
              {featureSchema.feature_names.map((name) => (
                <details key={name} className="pa-schema-item">
                  <summary>{name}</summary>
                  <p>{featureSchema.descriptions?.[name] || '—'}</p>
                </details>
              ))}
            </div>
          </section>
        )}

        <section className="pa-panel train-panel">
          <h2>
            <Icon name="barChart" size={20} /> 模型重训（合并已标注会话）
          </h2>
          <p className="muted small">
            在默认 goodx.csv / badx.csv 上，把你标注为「正常 / 恶意」的会话 pcap 再提取特征合并后重新训练随机森林（class_weight 平衡 + 基线对比），并覆盖保存
            model.pkl；重训后请重新检测 pcap（特征维度已扩展）。
          </p>
          <label className="pa-check">
            <input
              type="checkbox"
              checked={includeLabeledInTrain}
              onChange={(e) => setIncludeLabeledInTrain(e.target.checked)}
            />
            合并我已标注的抓包会话（取消则仅用原始 CSV 重训）
          </label>
          <button
            type="button"
            className="pa-btn primary"
            disabled={trainLoading || busy}
            onClick={handleTrainRebuild}
          >
            {trainLoading ? '训练中（可能数十秒）…' : '开始重训'}
          </button>
        </section>

        {lastTrainMetrics && (
          <section className="pa-panel metrics-panel">
            <h2>
              <Icon name="chart" size={20} /> 本次训练评估
            </h2>
            <div className="pa-metrics-grid">
              <div className="pa-metric-card">
                <span className="label">测试准确率</span>
                <strong>{lastTrainMetrics.test_score != null ? `${(lastTrainMetrics.test_score * 100).toFixed(2)}%` : '—'}</strong>
              </div>
              <div className="pa-metric-card">
                <span className="label">恶意 Recall</span>
                <strong>{lastTrainMetrics.malicious_recall != null ? `${(lastTrainMetrics.malicious_recall * 100).toFixed(2)}%` : '—'}</strong>
              </div>
              <div className="pa-metric-card">
                <span className="label">恶意 F1</span>
                <strong>{lastTrainMetrics.malicious_f1 != null ? `${(lastTrainMetrics.malicious_f1 * 100).toFixed(2)}%` : '—'}</strong>
              </div>
            </div>

            {lastTrainMetrics.confusion_matrix?.matrix && (
              <div className="pa-cm-block">
                <h3>混淆矩阵（测试集）</h3>
                <p className="muted small">{lastTrainMetrics.confusion_matrix.description}</p>
                <table className="pa-table pa-cm-table">
                  <thead>
                    <tr>
                      <th />
                      <th>预测恶意</th>
                      <th>预测安全</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th>真实恶意</th>
                      <td>{lastTrainMetrics.confusion_matrix.matrix[0]?.[0]}</td>
                      <td>{lastTrainMetrics.confusion_matrix.matrix[0]?.[1]}</td>
                    </tr>
                    <tr>
                      <th>真实安全</th>
                      <td>{lastTrainMetrics.confusion_matrix.matrix[1]?.[0]}</td>
                      <td>{lastTrainMetrics.confusion_matrix.matrix[1]?.[1]}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            {lastTrainMetrics.feature_importance?.length > 0 && (
              <div className="pa-sub-block">
                <h3>特征重要性（随机森林 Top）</h3>
                <ul className="pa-importance-list">
                  {lastTrainMetrics.feature_importance.map((f) => (
                    <li key={f.name}>
                      <span>{f.name}</span>
                      <div className="pa-imp-bar">
                        <div
                          className="pa-imp-fill"
                          style={{
                            width: `${Math.min(100, (f.importance / (lastTrainMetrics.feature_importance[0]?.importance || 1)) * 100)}%`,
                          }}
                        />
                      </div>
                      <span className="num">{(f.importance * 100).toFixed(2)}%</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {lastTrainMetrics.baseline_comparison?.length > 0 && (
              <div className="pa-sub-block">
                <h3>基线模型对比（同一测试集）</h3>
                <div className="table-scroll">
                  <table className="pa-table">
                    <thead>
                      <tr>
                        <th>算法</th>
                        <th>测试准确率</th>
                        <th>恶意 Recall</th>
                        <th>恶意 F1</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr className="highlight">
                        <td>RandomForest（主模型）</td>
                        <td>{lastTrainMetrics.test_score != null ? `${(lastTrainMetrics.test_score * 100).toFixed(2)}%` : '—'}</td>
                        <td>{lastTrainMetrics.malicious_recall != null ? `${(lastTrainMetrics.malicious_recall * 100).toFixed(2)}%` : '—'}</td>
                        <td>{lastTrainMetrics.malicious_f1 != null ? `${(lastTrainMetrics.malicious_f1 * 100).toFixed(2)}%` : '—'}</td>
                      </tr>
                      {lastTrainMetrics.baseline_comparison.map((b) => (
                        <tr key={b.algorithm}>
                          <td>{b.algorithm}</td>
                          <td>{b.test_accuracy != null ? `${(b.test_accuracy * 100).toFixed(2)}%` : '—'}</td>
                          <td>{b.malicious_recall != null ? `${(b.malicious_recall * 100).toFixed(2)}%` : '—'}</td>
                          <td>{b.malicious_f1 != null ? `${(b.malicious_f1 * 100).toFixed(2)}%` : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        )}

        <section className="pa-panel runs-panel">
          <h2>
            <Icon name="history" size={20} /> 训练记录（MongoDB model_runs）
          </h2>
          {modelRuns.length === 0 ? (
            <p className="muted">完成一次重训后会显示在此</p>
          ) : (
            <div className="table-scroll">
              <table className="pa-table">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>测试准确率</th>
                    <th>恶意 Recall</th>
                    <th>恶意 F1</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {modelRuns.map((r) => (
                    <Fragment key={r.id}>
                      <tr>
                        <td className="muted">
                          {r.created_at ? new Date(r.created_at).toLocaleString('zh-CN') : '—'}
                        </td>
                        <td>{r.test_score != null ? `${(r.test_score * 100).toFixed(2)}%` : '—'}</td>
                        <td>{r.malicious_recall != null ? `${(r.malicious_recall * 100).toFixed(2)}%` : '—'}</td>
                        <td>{r.malicious_f1 != null ? `${(r.malicious_f1 * 100).toFixed(2)}%` : '—'}</td>
                        <td className="pa-run-actions">
                          <button
                            type="button"
                            className="pa-btn pa-btn-sm"
                            onClick={() => setExpandedRunId(expandedRunId === r.id ? null : r.id)}
                          >
                            {expandedRunId === r.id ? '收起' : '详情'}
                          </button>
                          <button
                            type="button"
                            className="pa-btn pa-btn-sm"
                            disabled={!r.can_restore || restoreRunId != null || trainLoading || busy}
                            onClick={() => handleRestoreModelRun(r.id)}
                          >
                            {restoreRunId === r.id ? '恢复中…' : '恢复'}
                          </button>
                        </td>
                      </tr>
                      {expandedRunId === r.id && r.confusion_matrix?.matrix && (
                        <tr key={`${r.id}-detail`} className="pa-run-detail-row">
                          <td colSpan={5}>
                            <span className="muted small">混淆矩阵 </span>
                            <code>
                              {JSON.stringify(r.confusion_matrix.matrix)}
                            </code>
                            {r.feature_importance?.length > 0 && (
                              <span className="muted small">
                                {' '}
                                · Top 特征: {r.feature_importance.slice(0, 3).map((f) => f.name).join(', ')}
                              </span>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
      <style>{pageStyles}</style>
    </div>
  )
}

const pageStyles = `
  .pa-page { min-height: 100vh; background: var(--bg-dark); }
  .pa-main { max-width: 1280px; margin: 0 auto; padding: 28px 32px 56px; }
  .pa-center { display: flex; align-items: center; justify-content: center; min-height: 50vh; }
  .spinning { animation: pa-spin 0.9s linear infinite; }
  @keyframes pa-spin { to { transform: rotate(360deg); } }
  .pa-page-head { margin-bottom: 28px; }
  .pa-page-head h1 {
    color: var(--text-primary);
    font-size: clamp(22px, 2.5vw, 28px);
    font-weight: 700;
    letter-spacing: -0.02em;
    margin: 0 0 8px;
    background: linear-gradient(120deg, #fff 0%, var(--primary-light) 55%, var(--primary) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .pa-page-head p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 14px;
    line-height: 1.55;
    max-width: 560px;
  }
  .pa-banner {
    display: flex; align-items: center; gap: 10px; padding: 12px 16px; margin-bottom: 16px;
    border-radius: 12px; background: rgba(255,59,48,0.12); border: 1px solid rgba(255,59,48,0.35); color: #ff6b6b; font-size: 14px;
  }
  .pa-toolbar {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
    padding: 16px; background: #1a1a1a; border: 1px solid #333; border-radius: 16px; margin-bottom: 16px;
  }
  .pa-btn {
    padding: 8px 16px; border-radius: 10px; border: 1px solid #444; background: #252525; color: #eee;
    font-size: 13px; cursor: pointer;
  }
  .pa-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .pa-btn-sm { padding: 4px 10px; font-size: 12px; }
  .pa-btn.primary {
    background: linear-gradient(90deg, #ab08e3, #c73ef5); border-color: transparent; color: #fff; font-weight: 600;
  }
  .bpf-label { display: flex; align-items: center; gap: 8px; color: #aaa; font-size: 13px; margin-left: auto; }
  .bpf-input {
    width: 220px; padding: 8px 12px; border-radius: 8px; border: 1px solid #444; background: #111; color: #fff;
  }
  .pa-stats {
    display: flex; gap: 24px; color: #aaa; font-size: 13px; margin-bottom: 16px; align-items: center;
  }
  .pa-stats span { display: flex; align-items: center; gap: 6px; }
  .pa-sniff-error {
    display: flex; align-items: flex-start; gap: 10px; padding: 12px 14px; margin-bottom: 12px;
    border-radius: 12px; background: rgba(255, 193, 7, 0.12); border: 1px solid rgba(255, 193, 7, 0.4);
    color: #ffc14d; font-size: 13px; line-height: 1.5;
  }
  .hint { margin: 0 0 12px; font-size: 12px; }
  .pa-panels { display: grid; grid-template-columns: 1.2fr 1fr; gap: 16px; margin-bottom: 16px; }
  @media (max-width: 960px) { .pa-panels { grid-template-columns: 1fr; } }
  .pa-panel {
    background: #1a1a1a; border: 1px solid #333; border-radius: 16px; padding: 16px 18px; min-height: 200px;
  }
  .pa-panel h2 {
    display: flex; align-items: center; gap: 8px; color: #fff; font-size: 16px; margin: 0 0 12px; font-weight: 600;
  }
  .packet-list { max-height: 360px; overflow: auto; border: 1px solid #2a2a2a; border-radius: 10px; }
  .pa-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .pa-table th {
    text-align: left; padding: 8px 10px; background: #252525; color: #888; position: sticky; top: 0; z-index: 1;
  }
  .pa-table td { padding: 8px 10px; color: #ddd; border-top: 1px solid #2a2a2a; }
  .pa-table.compact tbody tr { cursor: pointer; }
  .pa-table.compact tbody tr:hover { background: #252525; }
  .pa-table.compact tbody tr.selected { background: rgba(171,8,227,0.15); }
  .info-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dissect-wrap { max-height: 360px; overflow: auto; font-size: 12px; color: #ccc; }
  .dissect-list { list-style: none; margin: 0; padding-left: 0; }
  .dissect-list.depth-1 { padding-left: 12px; }
  .dissect-list.depth-2 { padding-left: 24px; }
  .dissect-list.depth-3 { padding-left: 36px; }
  .dissect-line { font-family: ui-monospace, monospace; line-height: 1.6; }
  .checksum-box {
    margin-top: 12px; padding: 10px; border-radius: 8px; background: #252525; display: flex; gap: 12px; flex-wrap: wrap; font-size: 12px; color: #9cf;
  }
  .hex-panel { margin-bottom: 16px; }
  .hex-panel .hex-pre {
    margin: 0; padding: 12px; background: #111; border-radius: 10px; border: 1px solid #2a2a2a;
    color: #8f8; font-size: 11px; line-height: 1.5; overflow: auto; max-height: 200px; font-family: ui-monospace, monospace;
  }
  .muted { color: #666; font-size: 13px; margin: 8px; }
  .muted.small { font-size: 12px; margin: 0 0 14px; line-height: 1.5; }
  .table-scroll { overflow-x: auto; max-width: 100%; }
  .fname-cell { max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .annotate-cell { white-space: nowrap; }
  .pa-mini {
    padding: 4px 8px; margin: 2px; font-size: 11px; border-radius: 6px;
    border: 1px solid #444; background: #2a2a2a; color: #ccc; cursor: pointer;
  }
  .pa-mini:hover { border-color: #ab08e3; color: #fff; }
  .pa-tag { display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .pa-tag.good { background: rgba(52,199,89,0.2); color: #34c759; }
  .pa-tag.bad { background: rgba(255,59,48,0.2); color: #ff6b6b; }
  .pa-tag.muted { background: #333; color: #888; font-weight: 400; }
  .preview-toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 14px; }
  .pa-select {
    padding: 8px 12px; border-radius: 8px; border: 1px solid #444; background: #111; color: #fff;
    min-width: 200px; font-size: 13px;
  }
  .preview-summary { color: #ccc; font-size: 14px; display: flex; align-items: center; gap: 8px; margin: 0 0 12px; }
  .feature-panel, .train-panel, .runs-panel, .sessions-panel, .schema-panel, .metrics-panel { margin-bottom: 16px; }
  .pa-check { display: flex; align-items: center; gap: 8px; color: #aaa; font-size: 13px; margin: 12px 0; cursor: pointer; }
  .train-panel .pa-btn.primary { margin-top: 8px; }
  .pa-schema-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; max-height: 280px; overflow-y: auto; }
  .pa-schema-item { background: rgba(0,0,0,0.25); border: 1px solid #2a2a2a; border-radius: 10px; padding: 8px 10px; }
  .pa-schema-item summary { cursor: pointer; color: var(--primary-light); font-size: 13px; font-weight: 600; }
  .pa-schema-item p { margin: 8px 0 0; font-size: 12px; color: var(--text-secondary); line-height: 1.45; }
  .pa-metrics-grid { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
  .pa-metric-card { flex: 1; min-width: 120px; padding: 12px 14px; border-radius: 12px; background: rgba(171,8,227,0.1); border: 1px solid rgba(171,8,227,0.25); }
  .pa-metric-card .label { display: block; font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; }
  .pa-metric-card strong { font-size: 20px; color: #fff; }
  .pa-sub-block { margin-top: 18px; }
  .pa-sub-block h3 { color: #ddd; font-size: 14px; margin: 0 0 10px; }
  .pa-cm-table th, .pa-cm-table td { text-align: center; }
  .pa-importance-list { list-style: none; margin: 0; padding: 0; }
  .pa-importance-list li { display: grid; grid-template-columns: 120px 1fr 52px; gap: 10px; align-items: center; margin-bottom: 8px; font-size: 12px; color: #ccc; }
  .pa-imp-bar { height: 6px; background: #2a2a2a; border-radius: 999px; overflow: hidden; }
  .pa-imp-fill { height: 100%; background: linear-gradient(90deg, var(--primary), var(--primary-light)); }
  .pa-importance-list .num { text-align: right; color: #aaa; font-variant-numeric: tabular-nums; }
  .pa-table tr.highlight td { color: var(--primary-light); font-weight: 600; }
  .pa-run-actions { display: flex; flex-wrap: wrap; gap: 6px; }
  .pa-run-detail-row td { background: rgba(0,0,0,0.2); font-size: 12px; }
`
