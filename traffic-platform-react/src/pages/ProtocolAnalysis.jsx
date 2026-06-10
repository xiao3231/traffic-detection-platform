import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, formatUtcTime, readJsonResponse } from '../api'

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

const PROTOCOL_TAG_OPTIONS = ['TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'DNS', 'TLS']

function inferTagsFromBpf(bpf) {
  const expr = (bpf || '').toLowerCase()
  if (!expr) return []
  const found = []
  const pairs = [
    ['tcp port 80', 'HTTP'],
    ['udp', 'UDP'],
    ['tcp', 'TCP'],
    ['icmp', 'ICMP'],
    ['arp', 'ARP'],
    ['dns', 'DNS'],
    ['tls', 'TLS'],
  ]
  pairs.forEach(([token, tag]) => {
    if (expr.includes(token) && !found.includes(tag)) found.push(tag)
  })
  return found
}

const BPF_SELECT_OPTIONS = [
  { value: '', label: '请选择协议', expr: '' },
  { value: 'tcp', label: 'TCP', expr: 'tcp' },
  { value: 'udp', label: 'UDP', expr: 'udp' },
  { value: 'icmp', label: 'ICMP', expr: 'icmp' },
  { value: 'arp', label: 'ARP', expr: 'arp' },
  { value: 'http', label: 'HTTP (tcp port 80)', expr: 'tcp port 80' },
  { value: 'tcp_udp', label: 'TCP + UDP', expr: 'tcp or udp' },
  { value: 'custom', label: '自定义表达式', expr: null },
]

function isOfflineCaptureSession(session) {
  return Boolean(session?.source_file)
}

export default function ProtocolAnalysis() {
  const navigate = useNavigate()
  const fileRef = useRef(null)
  const listRef = useRef(null)

  const [ready, setReady] = useState(false)
  const [bpf, setBpf] = useState('')
  const [bpfSelect, setBpfSelect] = useState('')
  const [appliedBpf, setAppliedBpf] = useState('')
  const [hasOfflineSource, setHasOfflineSource] = useState(false)
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
  const [previewProbThreshold, setPreviewProbThreshold] = useState(0.8)
  const [previewRatioThreshold, setPreviewRatioThreshold] = useState(0.2)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewSessionId, setPreviewSessionId] = useState('')
  const [sniffError, setSniffError] = useState('')
  const [featureSchema, setFeatureSchema] = useState(null)

  const loadSessions = useCallback(async () => {
    const res = await fetch(apiUrl('/api/capture/sessions'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setSessions(data.items || [])
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
      setAppliedBpf(data.bpf_filter || '')
      setHasOfflineSource(!!data.has_offline_source)
      if (data.last_error) setSniffError(data.last_error)
    }
    return data
  }, [])

  const syncAllPackets = useCallback(async () => {
    const res = await fetch(apiUrl('/api/capture/packets'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (!res.ok) return data
    setPackets(data.packets || [])
    if (data.packet_count != null) setPacketCount(data.packet_count)
    if (data.status) {
      setRunning(!!data.status.running)
      setPaused(!!data.status.paused)
      setAppliedBpf(data.status.bpf_filter || '')
      setHasOfflineSource(!!data.status.has_offline_source)
      if (data.status.last_error) setSniffError(data.status.last_error)
    }
    return data
  }, [])

  const waitCaptureDone = useCallback(async () => {
    for (let i = 0; i < 400; i += 1) {
      const res = await fetch(apiUrl('/api/capture/pending'), { credentials: 'include' })
      const data = await readJsonResponse(res)
      if (data.status) {
        setRunning(!!data.status.running)
        setPaused(!!data.status.paused)
        setPacketCount(data.status.packet_count ?? 0)
        if (data.status.last_error) setSniffError(data.status.last_error)
      }
      if (data.packets?.length) {
        setPackets((prev) => [...prev, ...data.packets])
      }
      if (!data.status?.running) break
      await new Promise((r) => setTimeout(r, 150))
    }
    return syncAllPackets()
  }, [syncAllPackets])

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

  /** 抓包/离线解析结束时同步完整列表（离线很快完成时轮询可能来不及） */
  useEffect(() => {
    if (running) return undefined
    let cancelled = false
    const drain = async () => {
      try {
        const res = await fetch(apiUrl('/api/capture/pending'), { credentials: 'include' })
        const data = await readJsonResponse(res)
        if (cancelled) return
        if (data.packets?.length) {
          setPackets((prev) => [...prev, ...data.packets])
        }
        if (data.status?.packet_count != null) setPacketCount(data.status.packet_count)
        const full = await syncAllPackets()
        if (cancelled || !full?.packets?.length) return
        setPackets(full.packets)
      } catch {
        /* ignore */
      }
    }
    drain()
    return () => {
      cancelled = true
    }
  }, [running, syncAllPackets])

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
  }, [navigate, refreshStatus, loadSessions, loadFeatureSchema])

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
    if (data.session) {
      await loadSessions()
      alert(data.message || '会话已保存')
    } else if (data.message) {
      setError(data.message)
    }
    await refreshStatus()
  }

  const handleClear = async () => {
    await postAction('/api/capture/clear')
    setPackets([])
    setSelectedIndex(null)
    setDetail(null)
    setPacketCount(0)
    setSniffError('')
    setBpf('')
    setBpfSelect('')
    setAppliedBpf('')
    setHasOfflineSource(false)
    await refreshStatus()
  }

  const handleBpfSelectChange = (value) => {
    setBpfSelect(value)
    const opt = BPF_SELECT_OPTIONS.find((o) => o.value === value)
    if (value === 'custom') {
      setBpf('')
      return
    }
    setBpf(opt?.expr || '')
  }

  const handleBpfApply = async () => {
    const expr = bpf.trim()
    if (!expr) {
      setError('请在下拉框选择协议，或选「自定义表达式」后填写，例如 tcp port 443')
      return
    }
    if (!hasOfflineSource) {
      setError('请先「打开 pcap」加载文件后再点「查询」')
      return
    }
    setBusy(true)
    setError(null)
    setSniffError('')
    try {
      const res = await fetch(apiUrl('/api/capture/apply-bpf'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bpf_filter: expr }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '过滤失败')
      setPackets([])
      setSelectedIndex(null)
      setDetail(null)
      setRunning(true)
      const done = await waitCaptureDone()
      setAppliedBpf(expr)
      if ((done?.packet_count ?? 0) === 0 && !done?.status?.last_error) {
        setError('没有匹配的数据包，请检查 BPF 表达式是否正确')
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const handleBpfCancel = async () => {
    if (!hasOfflineSource) {
      setBpf('')
      setBpfSelect('')
      setAppliedBpf('')
      setError(null)
      return
    }
    setBusy(true)
    setError(null)
    setSniffError('')
    try {
      const res = await fetch(apiUrl('/api/capture/cancel-bpf'), {
        method: 'POST',
        credentials: 'include',
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '取消过滤失败')
      setBpf('')
      setBpfSelect('')
      setAppliedBpf('')
      setPackets([])
      setSelectedIndex(null)
      setDetail(null)
      setRunning(true)
      await waitCaptureDone()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const handleFeaturePreview = async (useSession) => {
    setPreviewLoading(true)
    setError(null)
    try {
      const body = {
        prob_threshold: previewProbThreshold,
        ratio_threshold: previewRatioThreshold,
        ...(useSession && previewSessionId ? { session_id: previewSessionId } : {}),
      }
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

  const handleAnnotate = async (sessionId, annotation, protocolTags) => {
    setError(null)
    try {
      const session = sessions.find((s) => s.id === sessionId)
      const tags =
        protocolTags ??
        (session?.protocol_tags?.length ? session.protocol_tags : inferTagsFromBpf(session?.bpf_filter))
      const payload =
        annotation === '' || annotation === null || annotation === undefined
          ? { annotation: null }
          : { annotation, protocol_tags: tags }
      const res = await fetch(apiUrl(`/api/capture/sessions/${sessionId}/annotate`), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '标注失败')
      await loadSessions()
    } catch (e) {
      setError(e.message)
    }
  }

  const handleToggleProtocolTag = async (sessionId, tag) => {
    const session = sessions.find((s) => s.id === sessionId)
    if (!session) return
    const current = session.protocol_tags?.length
      ? [...session.protocol_tags]
      : inferTagsFromBpf(session.bpf_filter)
    const next = current.includes(tag) ? current.filter((t) => t !== tag) : [...current, tag]
    setError(null)
    try {
      const res = await fetch(apiUrl(`/api/capture/sessions/${sessionId}/annotate`), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ protocol_tags: next }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '更新协议标签失败')
      await loadSessions()
    } catch (e) {
      setError(e.message)
    }
  }

  const handleToggleTrainingPool = async (sessionId, selected) => {
    setError(null)
    setSessions((prev) =>
      prev.map((s) => (s.id === sessionId ? { ...s, training_selected: selected } : s))
    )
    try {
      const res = await fetch(apiUrl(`/api/capture/sessions/${sessionId}/training-pool`), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selected }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '操作失败')
      await loadSessions()
    } catch (e) {
      setError(e.message)
      await loadSessions()
    }
  }

  const handleDeleteSession = async (sessionId, filename) => {
    const label = filename || sessionId
    if (!window.confirm(`确定删除会话「${label}」？\n将同时删除 MongoDB 记录与 pcap 文件。`)) return
    setError(null)
    try {
      const res = await fetch(apiUrl(`/api/capture/sessions/${sessionId}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '删除失败')
      if (previewSessionId === sessionId) setPreviewSessionId('')
      await loadSessions()
    } catch (e) {
      setError(e.message)
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
      setRunning(true)
      const done = await waitCaptureDone()
      setAppliedBpf('')
      setHasOfflineSource(!!done?.status?.has_offline_source)
      if ((done?.packet_count ?? 0) === 0 && !done?.status?.last_error) {
        setError('未解析到数据包，请确认文件为有效 .pcap 且非空')
      }
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

  const canSaveCapture = running || (hasOfflineSource && packetCount > 0)

  return (
    <div className="pa-page">
      <Header />
      <main className="pa-main">
        <header className="pa-page-head">
          <h1>抓包协议分析</h1>
          <p>实时抓包 / 离线 pcap · 协议解析 · 特征预览 · 会话标注与训练池入选</p>
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
          <button
            type="button"
            className="pa-btn"
            disabled={!canSaveCapture || busy}
            onClick={handleStop}
            title={hasOfflineSource && !running ? '将当前离线 pcap 写入已保存会话' : '停止抓包并保存会话'}
          >
            {running ? '停止并保存' : '保存会话'}
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
          <input ref={fileRef} type="file" accept=".pcap,.pcapng" hidden onChange={handleOpenPcap} />
          <div className="bpf-wrap">
            <span className="bpf-label-text">BPF 过滤器</span>
            <select
              className="bpf-select"
              value={bpfSelect}
              onChange={(ev) => handleBpfSelectChange(ev.target.value)}
              disabled={running || busy}
              aria-label="协议过滤"
            >
              {BPF_SELECT_OPTIONS.map((opt) => (
                <option key={opt.value || 'none'} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            {bpfSelect === 'custom' ? (
              <input
                className="bpf-input"
                value={bpf}
                onChange={(ev) => setBpf(ev.target.value)}
                onKeyDown={(ev) => {
                  if (ev.key === 'Enter' && !running && !busy && hasOfflineSource) handleBpfApply()
                }}
                placeholder="例如 tcp port 443"
                disabled={running || busy}
              />
            ) : null}
            <button
              type="button"
              className="pa-btn pa-btn-sm bpf-btn"
              disabled={running || busy || !hasOfflineSource}
              onClick={handleBpfApply}
              title={hasOfflineSource ? '对当前 pcap 应用 BPF' : '请先打开 pcap 文件'}
            >
              查询
            </button>
            <button
              type="button"
              className="pa-btn pa-btn-sm bpf-btn"
              disabled={running || busy || !hasOfflineSource}
              onClick={handleBpfCancel}
              title="清除过滤并重新加载全部数据包"
            >
              取消
            </button>
          </div>
        </div>

        <div className="pa-stats">
          <span>
            <Icon name="scan" size={18} /> 缓冲包数：{packetCount}
            {packetCount >= 5000 ? '（已达上限 5000）' : ''}
          </span>
          <span>
            <Icon name="info" size={18} /> 状态：{running ? (paused ? '已暂停' : '抓包中') : '空闲'}
          </span>
          {appliedBpf ? (
            <span>
              <Icon name="scan" size={18} /> 已应用 BPF：<code className="bpf-applied">{appliedBpf}</code>
            </span>
          ) : null}
          {hasOfflineSource && !appliedBpf ? (
            <span className="muted-inline">
              离线 pcap 已加载，可先点「保存会话」写入列表，或选协议后点「查询」过滤
            </span>
          ) : null}
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
            <p className="muted">实时抓包点「停止」或离线打开 pcap 后点「停止」会写入 capture_sessions</p>
          ) : (
            <div className="table-scroll">
              <table className="pa-table">
                <thead>
                  <tr>
                    <th>模式</th>
                    <th>包数</th>
                    <th>文件</th>
                    <th>标注</th>
                    <th>训练池</th>
                    <th>协议</th>
                    <th>时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => {
                    const offline = isOfflineCaptureSession(s)
                    return (
                    <tr key={s.id}>
                      <td>
                        <span className={`pa-mode-tag${offline ? ' offline' : ' live'}`}>
                          {offline ? '离线' : '实时'}
                        </span>
                      </td>
                      <td>{s.packet_count}</td>
                      <td
                        className="fname-cell"
                        title={
                          offline && s.source_file && s.pcap_filename
                            ? `已保存为 ${s.pcap_filename}`
                            : undefined
                        }
                      >
                        {offline && s.source_file ? s.source_file : s.pcap_filename || '—'}
                      </td>
                      <td>
                        {!s.annotation && <span className="pa-tag muted">未标注</span>}
                        {s.annotation === 'normal' && <span className="pa-tag good">正常样本</span>}
                        {s.annotation === 'malicious' && <span className="pa-tag bad">恶意样本</span>}
                      </td>
                      <td>
                        {!s.annotation ? (
                          <span className="muted small">—</span>
                        ) : (
                          <button
                            type="button"
                            className={`pa-pool-toggle${s.training_selected ? ' on' : ''}`}
                            onClick={() => handleToggleTrainingPool(s.id, !s.training_selected)}
                            title="点击切换是否加入训练池"
                          >
                            {s.training_selected ? '已入选' : '未入选'}
                          </button>
                        )}
                      </td>
                      <td className="pa-tag-cell">
                        <div className="pa-protocol-tags">
                          {PROTOCOL_TAG_OPTIONS.map((tag) => {
                            const active = (s.protocol_tags?.length
                              ? s.protocol_tags
                              : inferTagsFromBpf(s.bpf_filter)
                            ).includes(tag)
                            return (
                              <button
                                key={tag}
                                type="button"
                                className={`pa-tag-btn${active ? ' on' : ''}`}
                                onClick={() => handleToggleProtocolTag(s.id, tag)}
                                title="点击切换协议标签"
                              >
                                {tag}
                              </button>
                            )
                          })}
                        </div>
                      </td>
                      <td className="muted" title={offline ? '上传 pcap 时间' : '抓包结束时间'}>
                        {formatUtcTime(s.ended_at)}
                      </td>
                      <td className="annotate-cell">
                        <button type="button" className="pa-mini" onClick={() => handleAnnotate(s.id, 'normal')}>
                          标正常
                        </button>
                        <button type="button" className="pa-mini" onClick={() => handleAnnotate(s.id, 'malicious')}>
                          标恶意
                        </button>
                        {s.annotation ? (
                          <button
                            type="button"
                            className="pa-mini"
                            onClick={() => handleAnnotate(s.id, null)}
                          >
                            清除标注
                          </button>
                        ) : null}
                        {s.annotation && !s.training_selected ? (
                          <button
                            type="button"
                            className="pa-mini"
                            onClick={() => handleToggleTrainingPool(s.id, true)}
                          >
                            加入训练
                          </button>
                        ) : null}
                        {s.annotation && s.training_selected ? (
                          <button
                            type="button"
                            className="pa-mini"
                            onClick={() => handleToggleTrainingPool(s.id, false)}
                          >
                            移出训练
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="pa-mini danger"
                          onClick={() => handleDeleteSession(s.id, s.pcap_filename)}
                        >
                          删除
                        </button>
                      </td>
                    </tr>
                    )
                  })}
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
            按「流」聚合为 17 维特征；显示每条流的硬分类与<strong>恶意概率 P(0)</strong>。文件级结论采用阈值策略（非任一流恶意即整包危险）：存在
            P≥概率阈值 的流，或恶意流占比&gt;占比阈值 时判危险。
          </p>
          <div className="preview-threshold-row">
            <label className="preview-th-field">
              <span>恶意概率阈值</span>
              <input
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={previewProbThreshold}
                onChange={(e) => setPreviewProbThreshold(Number(e.target.value))}
              />
            </label>
            <label className="preview-th-field">
              <span>恶意流占比阈值</span>
              <input
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={previewRatioThreshold}
                onChange={(e) => setPreviewRatioThreshold(Number(e.target.value))}
              />
            </label>
          </div>
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
              {featurePreview.file_decision && (
                <p className="muted small preview-file-decision">
                  文件级判定：
                  <strong className={featurePreview.file_decision.is_safe ? 'good' : 'bad'}>
                    {featurePreview.file_decision.label}
                  </strong>
                  （P 阈值 {featurePreview.file_decision.prob_threshold}，占比阈值{' '}
                  {(featurePreview.file_decision.ratio_threshold * 100).toFixed(0)}%）
                </p>
              )}
              {featurePreview.flow_count === 0 ? (
                <p className="muted">未形成流级特征，可多抓一些包或换 pcap。</p>
              ) : (
                <div className="table-scroll">
                  <table className="pa-table compact">
                    <thead>
                      <tr>
                        <th>流#</th>
                        <th>模型预测</th>
                        <th>P(恶意)</th>
                        <th>len_mean</th>
                        <th>len_std</th>
                        <th>time_mean</th>
                        <th>time_std</th>
                        <th>…</th>
                      </tr>
                    </thead>
                    <tbody>
                      {featurePreview.flows.map((f) => (
                        <tr key={f.index} className={f.high_risk ? 'high-risk-row' : ''}>
                          <td>{f.index}</td>
                          <td>
                            <span className={f.prediction === 1 ? 'pa-tag good' : 'pa-tag bad'}>
                              {f.prediction_label}
                            </span>
                          </td>
                          <td>
                            {f.malicious_prob != null ? `${(f.malicious_prob * 100).toFixed(1)}%` : '—'}
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
  .bpf-wrap {
    display: flex; align-items: center; gap: 8px; margin-left: auto; flex-wrap: wrap;
    max-width: 100%;
  }
  .bpf-label-text { color: #aaa; font-size: 13px; white-space: nowrap; }
  .bpf-select {
    min-width: 168px; padding: 8px 32px 8px 12px; border-radius: 8px; border: 1px solid #444;
    background: #111 url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23aaa' d='M2 4l4 4 4-4'/%3E%3C/svg%3E") no-repeat right 10px center;
    color: #fff; font-size: 13px; cursor: pointer; appearance: none;
  }
  .bpf-select:disabled { opacity: 0.45; cursor: not-allowed; }
  .bpf-input {
    width: min(200px, 100%); padding: 8px 12px; border-radius: 8px; border: 1px solid #444; background: #111; color: #fff;
  }
  .bpf-btn { flex-shrink: 0; }
  .bpf-applied { color: #c9a0ff; font-size: 12px; }
  .muted-inline { color: #777; font-size: 12px; }
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
  .pa-mini.danger { color: #ff8a8a; border-color: #633; }
  .pa-mini.danger:hover { background: rgba(255, 80, 80, 0.12); }
  .pa-mini {
    padding: 4px 8px; margin: 2px; font-size: 11px; border-radius: 6px;
    border: 1px solid #444; background: #2a2a2a; color: #ccc; cursor: pointer;
  }
  .pa-mini:hover { border-color: #ab08e3; color: #fff; }
  .pa-tag { display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .pa-tag.good { background: rgba(52,199,89,0.2); color: #34c759; }
  .pa-tag.bad { background: rgba(255,59,48,0.2); color: #ff6b6b; }
  .pa-tag.muted { background: #333; color: #888; font-weight: 400; }
  .pa-mode-tag {
    display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600;
  }
  .pa-mode-tag.live { background: rgba(10, 132, 255, 0.18); color: #5ac8fa; }
  .pa-mode-tag.offline { background: rgba(255, 159, 10, 0.15); color: #ffb340; }
  .preview-threshold-row {
    display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 12px; align-items: flex-end;
  }
  .preview-th-field { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: #aaa; }
  .preview-th-field input {
    width: 120px; padding: 8px 10px; border-radius: 8px; border: 1px solid #444;
    background: #111; color: #fff; font-size: 13px;
  }
  .preview-file-decision .good { color: #34c759; }
  .preview-file-decision .bad { color: #ff6b6b; }
  .pa-table tr.high-risk-row td { background: rgba(255, 80, 80, 0.08); }
  .preview-toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 14px; }
  .pa-select {
    padding: 8px 12px; border-radius: 8px; border: 1px solid #444; background: #111; color: #fff;
    min-width: 200px; font-size: 13px;
  }
  .preview-summary { color: #ccc; font-size: 14px; display: flex; align-items: center; gap: 8px; margin: 0 0 12px; }
  .feature-panel, .train-panel, .runs-panel, .sessions-panel, .schema-panel, .metrics-panel { margin-bottom: 16px; }
  .pa-check { display: flex; align-items: center; gap: 8px; color: #aaa; font-size: 13px; margin: 12px 0; cursor: pointer; }
  .pa-merge-mode-row { display: flex; flex-direction: column; gap: 8px; margin: 8px 0 12px; }
  .pa-merge-mode-label { color: #aaa; font-size: 13px; }
  .pa-radio { display: flex; align-items: center; gap: 8px; color: #bbb; font-size: 13px; cursor: pointer; }
  .pa-labeled-summary { margin: 0 0 12px; line-height: 1.5; }
  .pa-training-pool-table-wrap { margin: 12px 0 16px; }
  .pa-training-pool-title { margin: 0 0 8px; font-size: 14px; color: #ddd; font-weight: 600; }
  .pa-training-pool-table tr.pa-pool-in td { background: rgba(34, 197, 94, 0.05); }
  .pa-pool-toggle {
    border: 1px solid rgba(255,255,255,0.15);
    background: rgba(255,255,255,0.04);
    color: #aaa;
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
  }
  .pa-pool-toggle.on {
    border-color: rgba(34, 197, 94, 0.5);
    background: rgba(34, 197, 94, 0.15);
    color: #86efac;
  }
  .pa-pool-toggle:hover { filter: brightness(1.08); }
  .pa-baseline-details {
    margin-top: 12px;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 10px 14px;
    background: rgba(0,0,0,0.15);
  }
  .pa-baseline-details summary {
    cursor: pointer;
    color: #ccc;
    font-size: 14px;
    font-weight: 600;
    user-select: none;
  }
  .pa-baseline-policy { margin: 10px 0 8px; line-height: 1.55; }
  .pa-baseline-block { margin-top: 8px; }
  .pa-baseline-table td:first-child { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
  .pa-baseline-table tr.pa-baseline-primary td { background: rgba(34, 197, 94, 0.06); }
  .pa-merged-sessions-block { margin: 16px 0 12px; }
  .pa-merged-sessions-table { margin-top: 8px; }
  .pa-protocol-tags.readonly .pa-tag-btn.readonly {
    cursor: default; pointer-events: none; padding: 2px 8px; font-size: 11px;
  }
  .pa-protocol-tags { display: flex; flex-wrap: wrap; gap: 4px; min-width: 168px; }
  .pa-tag-btn {
    padding: 2px 6px; border-radius: 6px; border: 1px solid #444; background: #222;
    color: #888; font-size: 10px; cursor: pointer;
  }
  .pa-tag-btn.on { border-color: rgba(171, 8, 227, 0.6); color: #e8d0f5; background: rgba(171, 8, 227, 0.15); }
  .pa-tag-cell { vertical-align: top; }
  .pa-sample-merge-mode { margin: 0 0 8px; }
  .train-panel .pa-btn.primary { margin-top: 8px; }
  .pa-schema-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; max-height: 280px; overflow-y: auto; }
  .pa-schema-item { background: rgba(0,0,0,0.25); border: 1px solid #2a2a2a; border-radius: 10px; padding: 8px 10px; }
  .pa-schema-item summary { cursor: pointer; color: var(--primary-light); font-size: 13px; font-weight: 600; }
  .pa-schema-item p { margin: 8px 0 0; font-size: 12px; color: var(--text-secondary); line-height: 1.45; }
  .pa-metrics-hint { margin: 16px 0 0; }
  .pa-metrics-rf-hint { margin: 10px 0 0; line-height: 1.55; }
  .pa-metrics-subtitle { margin: -4px 0 12px; color: #888; }
  .metrics-panel { margin-top: 16px; }
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
  .pa-run-detail-row td { padding: 10px 12px 14px; background: rgba(0,0,0,0.2); border-top: none; }
  .pa-run-sample-detail { margin: 0 0 16px; line-height: 1.55; }
  .pa-sample-source-title { margin: 0 0 10px; font-size: 14px; color: #ddd; font-weight: 600; }
  .pa-sample-source-table { margin-bottom: 10px; font-size: 12px; }
  .pa-sample-source-table th { color: #aaa; font-weight: 500; white-space: nowrap; }
  .pa-sample-source-table td, .pa-sample-source-table th { padding: 8px 10px; }
  .pa-sample-total-row th, .pa-sample-total-row td { border-top: 1px solid #444; color: #ddd; }
  .pa-sample-split-line { margin: 0 0 4px; line-height: 1.55; }
  .pa-run-extra-detail { margin: 0; line-height: 1.5; }
  .pa-run-actions { display: flex; flex-wrap: wrap; gap: 6px; }
  .pa-run-detail-row td { background: rgba(0,0,0,0.2); font-size: 12px; }
  .pa-active-model-hint { margin: -4px 0 14px; }
  .pa-active-model-hint strong { color: var(--primary-light); font-weight: 600; }
  .pa-model-cell { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
  .pa-model-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    color: #0d1f12;
    background: linear-gradient(90deg, #4ade80, #22c55e);
    letter-spacing: 0.02em;
  }
  .pa-merge-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.02em;
    white-space: nowrap;
    cursor: help;
  }
  .pa-merge-badge.cumulative {
    color: #e8d4ff;
    background: rgba(171, 8, 227, 0.22);
    border: 1px solid rgba(171, 8, 227, 0.45);
  }
  .pa-merge-badge.pool {
    color: #bfdbfe;
    background: rgba(59, 130, 246, 0.18);
    border: 1px solid rgba(59, 130, 246, 0.45);
  }
  .pa-merge-badge.local {
    color: #a3a3a3;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.12);
  }
  .pa-table tr.pa-run-active td { background: rgba(34, 197, 94, 0.08); }
  .pa-table tr.pa-run-active td:first-child { box-shadow: inset 3px 0 0 #22c55e; }
  .pa-table tr.pa-run-viewing td { background: rgba(171, 8, 227, 0.08); }
  .pa-table tr.pa-run-viewing td:first-child { box-shadow: inset 3px 0 0 var(--primary); }
`
