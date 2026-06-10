import { useState, useEffect, useRef, useCallback, Fragment } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../../components/Header'
import Icon from '../../components/Icon'
import { TrainMetricsPanel, runMergeModeInfo } from '../../components/trainMetrics'
import { apiUrl, formatUtcTime, readJsonResponse } from '../../api'

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

function isOfflineCaptureSession(session) {
  return Boolean(session?.source_file)
}

export default function ModelRetrain() {
  const navigate = useNavigate()
  const metricsPanelRef = useRef(null)

  const [ready, setReady] = useState(false)
  const [sessions, setSessions] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [modelRuns, setModelRuns] = useState([])
  const [activeModel, setActiveModel] = useState(null)
  const [trainLoading, setTrainLoading] = useState(false)
  const [restoreRunId, setRestoreRunId] = useState(null)
  const [includeLabeledInTrain, setIncludeLabeledInTrain] = useState(true)
  const [trainingPoolSummary, setTrainingPoolSummary] = useState(null)
  const [viewingRunId, setViewingRunId] = useState(null)
  const [viewingRunDetail, setViewingRunDetail] = useState(null)
  const [viewingRunLoading, setViewingRunLoading] = useState(false)

  const loadSessions = useCallback(async () => {
    const res = await fetch(apiUrl('/api/capture/sessions'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setSessions(data.items || [])
  }, [])

  const loadTrainingPoolSummary = useCallback(async () => {
    const res = await fetch(apiUrl('/api/train/labeled-summary'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) setTrainingPoolSummary(data)
  }, [])

  const loadModelRuns = useCallback(async () => {
    const res = await fetch(apiUrl('/api/train/runs'), { credentials: 'include' })
    const data = await readJsonResponse(res)
    if (res.ok) {
      setModelRuns(data.items || [])
      setActiveModel(data.active_model || null)
    }
  }, [])

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
        await loadSessions()
        await loadModelRuns()
        await loadTrainingPoolSummary()
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
  }, [navigate, loadSessions, loadModelRuns, loadTrainingPoolSummary])

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
      await loadTrainingPoolSummary()
    } catch (e) {
      setError(e.message)
      await loadSessions()
    }
  }

  const handleViewRunMetrics = async (runId) => {
    if (viewingRunId === runId) {
      setViewingRunId(null)
      setViewingRunDetail(null)
      return
    }
    setViewingRunId(runId)
    setViewingRunDetail(null)
    setViewingRunLoading(true)
    setError(null)
    try {
      const res = await fetch(apiUrl(`/api/train/runs/${runId}`), { credentials: 'include' })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '加载训练评估失败')
      setViewingRunDetail(data.run)
      setModelRuns((prev) => prev.map((r) => (r.id === runId ? { ...r, ...data.run } : r)))
      requestAnimationFrame(() => {
        metricsPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      })
    } catch (e) {
      setError(e.message)
      setViewingRunId(null)
      setViewingRunDetail(null)
    } finally {
      setViewingRunLoading(false)
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
        body: JSON.stringify({
          include_labeled_captures: includeLabeledInTrain,
        }),
      })
      const data = await readJsonResponse(res)
      if (!res.ok) throw new Error(data.error || '训练失败')
      await loadModelRuns()
      await loadSessions()
      await loadTrainingPoolSummary()
      if (data.run_id) {
        await handleViewRunMetrics(data.run_id)
      }
      const m = data.metrics || {}
      alert(
        `训练完成（随机森林，${m.feature_count ?? '—'} 维特征）\n` +
          `训练样本: ${m.sample_total != null ? `${m.sample_total} 条（正常 ${m.sample_normal} / 恶意 ${m.sample_malicious}）` : '—'}\n` +
          `拟合/测试: ${m.train_set_size != null ? `${m.train_set_size} / ${m.test_set_size} 条` : '—'}\n` +
          `\n测试准确率: ${m.test_score != null ? (m.test_score * 100).toFixed(2) : '—'}%\n` +
          `恶意类 Recall: ${m.malicious_recall != null ? (m.malicious_recall * 100).toFixed(2) : '—'}%  F1: ${m.malicious_f1 != null ? (m.malicious_f1 * 100).toFixed(2) : '—'}%\n` +
          `训练池 pcap: ${data.merged_session_count ?? 0} 个\n` +
          `合并正常 pcap: ${data.merged_good_pcaps}，恶意: ${data.merged_bad_pcaps}\n` +
          '详见下方训练记录中的「评估」面板。'
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

  const viewingRun = viewingRunId
    ? (viewingRunDetail || modelRuns.find((r) => r.id === viewingRunId))
    : null

  if (!ready) {
    return (
      <div className="mt-page">
        <Header />
        <main className="mt-main mt-center">
          <Icon name="loading" size={40} className="spinning" />
        </main>
        <style>{pageStyles}</style>
      </div>
    )
  }

  return (
    <div className="mt-page">
      <Header />
      <main className="mt-main">
        <header className="mt-page-head">
          <h1>模型重训</h1>
          <p>管理训练样本池、触发模型重训，并查看训练记录、评估指标与历史版本恢复。</p>
        </header>

        {error && (
          <div className="mt-banner">
            <Icon name="error" size={20} />
            <span>{error}</span>
          </div>
        )}

        <section className="mt-panel train-panel">
          <h2>
            <Icon name="barChart" size={20} /> 模型重训（训练样本池）
          </h2>
          <p className="muted small">
            在默认 goodx/badx 基础上，合并<strong>训练样本池</strong>中已勾选的 pcap 后重训。请先在
            <strong> 抓包协议分析 </strong>
            页标注会话，再在此加入训练池；不需要的 pcap 可「移出训练」。
          </p>
          <label className="mt-check">
            <input
              type="checkbox"
              checked={includeLabeledInTrain}
              onChange={(e) => setIncludeLabeledInTrain(e.target.checked)}
            />
            合并训练样本池中的 pcap（取消则仅用 goodx/badx 重训）
          </label>
          {trainingPoolSummary && (
            <p className="muted small mt-labeled-summary">
              训练池：正常 {trainingPoolSummary.pool?.normal ?? 0} / 恶意{' '}
              {trainingPoolSummary.pool?.malicious ?? 0} 份（共{' '}
              {trainingPoolSummary.pool?.total ?? 0} 份）；
              已标注未入选：{trainingPoolSummary.labeled_not_in_pool?.total ?? 0} 份
            </p>
          )}
          {sessions.filter((s) => s.annotation).length > 0 ? (
            <div className="mt-training-pool-table-wrap">
              <h3 className="mt-training-pool-title">已标注会话 · 训练池管理</h3>
              <div className="table-scroll">
                <table className="mt-table mt-training-pool-table">
                  <thead>
                    <tr>
                      <th>文件</th>
                      <th>标注</th>
                      <th>协议</th>
                      <th>包数</th>
                      <th>状态</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions
                      .filter((s) => s.annotation)
                      .map((s) => {
                        const offline = isOfflineCaptureSession(s)
                        const fname = offline && s.source_file ? s.source_file : s.pcap_filename || '—'
                        const tags = s.protocol_tags?.length
                          ? s.protocol_tags
                          : inferTagsFromBpf(s.bpf_filter)
                        return (
                          <tr key={`pool-${s.id}`} className={s.training_selected ? 'mt-pool-in' : ''}>
                            <td className="fname-cell" title={fname}>
                              {fname}
                            </td>
                            <td>
                              {s.annotation === 'normal' ? (
                                <span className="mt-tag good">正常</span>
                              ) : (
                                <span className="mt-tag bad">恶意</span>
                              )}
                            </td>
                            <td className="muted small">{tags.length ? tags.join(', ') : '—'}</td>
                            <td>{s.packet_count}</td>
                            <td>
                              <button
                                type="button"
                                className={`mt-pool-toggle${s.training_selected ? ' on' : ''}`}
                                onClick={() => handleToggleTrainingPool(s.id, !s.training_selected)}
                                title="点击切换是否加入训练池"
                              >
                                {s.training_selected ? '已入选' : '未入选'}
                              </button>
                            </td>
                            <td>
                              <button
                                type="button"
                                className="mt-mini"
                                disabled={busy}
                                onClick={() => handleToggleTrainingPool(s.id, !s.training_selected)}
                              >
                                {s.training_selected ? '移出训练' : '加入训练'}
                              </button>
                            </td>
                          </tr>
                        )
                      })}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <p className="muted small">暂无已标注会话。请先在抓包协议分析页保存并标注会话。</p>
          )}
          <button
            type="button"
            className="mt-btn primary"
            disabled={trainLoading || busy}
            onClick={handleTrainRebuild}
          >
            {trainLoading ? '训练中（可能数十秒）…' : '开始重训'}
          </button>
        </section>

        <section className="mt-panel runs-panel">
          <h2>
            <Icon name="history" size={20} /> 训练记录
          </h2>
          {activeModel?.model_algorithm_label && (
            <p className="muted small mt-active-model-hint">
              当前检测使用模型：
              <strong>{activeModel.model_algorithm_label}</strong>
              {activeModel.run_id ? '（已关联下方训练记录）' : '（未匹配到历史训练快照）'}
            </p>
          )}
          {modelRuns.length === 0 ? (
            <p className="muted">完成一次重训后会显示在此</p>
          ) : (
            <div className="table-scroll">
              <table className="mt-table">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>模型</th>
                    <th>合并</th>
                    <th>测试准确率</th>
                    <th>恶意 Recall</th>
                    <th>恶意 F1</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {modelRuns.map((r) => (
                    <Fragment key={r.id}>
                      <tr
                        className={[
                          r.is_active ? 'mt-run-active' : '',
                          viewingRunId === r.id ? 'mt-run-viewing' : '',
                        ]
                          .filter(Boolean)
                          .join(' ') || undefined}
                      >
                        <td className="muted">{formatUtcTime(r.created_at)}</td>
                        <td>
                          <div className="mt-model-cell">
                            <span>{r.model_algorithm_label || r.model_algorithm || '随机森林'}</span>
                            {r.is_active && <span className="mt-model-badge">线上</span>}
                          </div>
                        </td>
                        <td>
                          {(() => {
                            const merge = runMergeModeInfo(r)
                            return (
                              <span className={`mt-merge-badge ${merge.variant}`} title={merge.title}>
                                {merge.text}
                              </span>
                            )
                          })()}
                        </td>
                        <td>{r.test_score != null ? `${(r.test_score * 100).toFixed(2)}%` : '—'}</td>
                        <td>
                          {r.malicious_recall != null ? `${(r.malicious_recall * 100).toFixed(2)}%` : '—'}
                        </td>
                        <td>{r.malicious_f1 != null ? `${(r.malicious_f1 * 100).toFixed(2)}%` : '—'}</td>
                        <td className="mt-run-actions">
                          <button
                            type="button"
                            className={`mt-btn mt-btn-sm${viewingRunId === r.id ? ' primary' : ''}`}
                            onClick={() => handleViewRunMetrics(r.id)}
                          >
                            {viewingRunId === r.id ? '收起评估' : '评估'}
                          </button>
                          <button
                            type="button"
                            className="mt-btn mt-btn-sm"
                            disabled={!r.can_restore || restoreRunId != null || trainLoading || busy}
                            onClick={() => handleRestoreModelRun(r.id)}
                          >
                            {restoreRunId === r.id ? '恢复中…' : '恢复'}
                          </button>
                        </td>
                      </tr>
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div ref={metricsPanelRef}>
            {viewingRunLoading ? (
              <p className="muted small mt-metrics-hint">正在加载训练评估与算法基线对比…</p>
            ) : viewingRun ? (
              <TrainMetricsPanel
                run={viewingRun}
                title={viewingRun.is_active ? '本次训练评估（线上）' : '训练记录评估'}
              />
            ) : (
              <p className="muted small mt-metrics-hint">
                点击训练记录中的「评估」查看合并的标注会话、算法基线对比、混淆矩阵与特征重要性
              </p>
            )}
          </div>
        </section>
      </main>
      <style>{pageStyles}</style>
    </div>
  )
}

const pageStyles = `
  .mt-page { min-height: 100vh; background: var(--bg-dark); }
  .mt-main { max-width: 1280px; margin: 0 auto; padding: 28px 32px 56px; }
  .mt-center { display: flex; align-items: center; justify-content: center; min-height: 50vh; }
  .spinning { animation: mt-spin 0.9s linear infinite; }
  @keyframes mt-spin { to { transform: rotate(360deg); } }
  .mt-page-head { margin-bottom: 28px; }
  .mt-page-head h1 {
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
  .mt-page-head p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 14px;
    line-height: 1.55;
    max-width: 640px;
  }
  .mt-banner {
    display: flex; align-items: center; gap: 10px; padding: 12px 16px; margin-bottom: 16px;
    border-radius: 12px; background: rgba(255,59,48,0.12); border: 1px solid rgba(255,59,48,0.35); color: #ff6b6b; font-size: 14px;
  }
  .mt-panel {
    background: #1a1a1a; border: 1px solid #333; border-radius: 16px; padding: 16px 18px; margin-bottom: 16px;
  }
  .mt-panel h2 {
    display: flex; align-items: center; gap: 8px; color: #fff; font-size: 16px; margin: 0 0 12px; font-weight: 600;
  }
  .mt-btn {
    padding: 8px 16px; border-radius: 10px; border: 1px solid #444; background: #252525; color: #eee;
    font-size: 13px; cursor: pointer;
  }
  .mt-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .mt-btn-sm { padding: 4px 10px; font-size: 12px; }
  .mt-btn.primary {
    background: linear-gradient(90deg, #ab08e3, #c73ef5); border-color: transparent; color: #fff; font-weight: 600;
  }
  .muted { color: #666; font-size: 13px; margin: 8px; }
  .muted.small { font-size: 12px; margin: 0 0 14px; line-height: 1.5; }
  .table-scroll { overflow-x: auto; max-width: 100%; }
  .mt-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .mt-table th {
    text-align: left; padding: 8px 10px; background: #252525; color: #888; position: sticky; top: 0; z-index: 1;
  }
  .mt-table td { padding: 8px 10px; color: #ddd; border-top: 1px solid #2a2a2a; }
  .fname-cell { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .mt-tag { display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .mt-tag.good { background: rgba(52,199,89,0.2); color: #34c759; }
  .mt-tag.bad { background: rgba(255,59,48,0.2); color: #ff6b6b; }
  .mt-mini {
    padding: 4px 8px; font-size: 11px; border-radius: 6px;
    border: 1px solid #444; background: #2a2a2a; color: #ccc; cursor: pointer;
  }
  .mt-mini:hover { border-color: #ab08e3; color: #fff; }
  .mt-check { display: flex; align-items: center; gap: 8px; color: #aaa; font-size: 13px; margin: 12px 0; cursor: pointer; }
  .mt-labeled-summary { margin: 0 0 12px; line-height: 1.5; }
  .mt-training-pool-table-wrap { margin: 12px 0 16px; }
  .mt-training-pool-title { margin: 0 0 8px; font-size: 14px; color: #ddd; font-weight: 600; }
  .mt-training-pool-table tr.mt-pool-in td { background: rgba(34, 197, 94, 0.05); }
  .mt-pool-toggle {
    border: 1px solid rgba(255,255,255,0.15);
    background: rgba(255,255,255,0.04);
    color: #aaa;
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
  }
  .mt-pool-toggle.on {
    border-color: rgba(34, 197, 94, 0.5);
    background: rgba(34, 197, 94, 0.15);
    color: #86efac;
  }
  .train-panel .mt-btn.primary { margin-top: 8px; }
  .mt-active-model-hint { margin: -4px 0 14px; }
  .mt-active-model-hint strong { color: var(--primary-light); font-weight: 600; }
  .mt-model-cell { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
  .mt-model-badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    color: #0d1f12; background: linear-gradient(90deg, #4ade80, #22c55e); letter-spacing: 0.02em;
  }
  .mt-merge-badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    white-space: nowrap; cursor: help;
  }
  .mt-merge-badge.pool {
    color: #bfdbfe; background: rgba(59, 130, 246, 0.18); border: 1px solid rgba(59, 130, 246, 0.45);
  }
  .mt-merge-badge.local {
    color: #a3a3a3; background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.12);
  }
  .mt-table tr.mt-run-active td { background: rgba(34, 197, 94, 0.08); }
  .mt-table tr.mt-run-active td:first-child { box-shadow: inset 3px 0 0 #22c55e; }
  .mt-table tr.mt-run-viewing td { background: rgba(171, 8, 227, 0.08); }
  .mt-table tr.mt-run-viewing td:first-child { box-shadow: inset 3px 0 0 var(--primary); }
  .mt-run-actions { display: flex; flex-wrap: wrap; gap: 6px; }
  .mt-metrics-hint { margin: 16px 0 0; }
  .mt-panel.metrics-panel, .metrics-panel {
    background: #1a1a1a; border: 1px solid #333; border-radius: 16px; padding: 16px 18px; margin-top: 16px;
  }
  .metrics-panel h2 {
    display: flex; align-items: center; gap: 8px; color: #fff; font-size: 16px; margin: 0 0 12px; font-weight: 600;
  }
  .pa-metrics-subtitle { margin: -4px 0 12px; color: #888; }
  .pa-metrics-grid { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
  .pa-metric-card { flex: 1; min-width: 120px; padding: 12px 14px; border-radius: 12px; background: rgba(171,8,227,0.1); border: 1px solid rgba(171,8,227,0.25); }
  .pa-metric-card .label { display: block; font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; }
  .pa-metric-card strong { font-size: 20px; color: #fff; }
  .pa-metrics-rf-hint { margin: 10px 0 0; line-height: 1.55; }
  .pa-baseline-details { margin-top: 12px; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 10px 14px; background: rgba(0,0,0,0.15); }
  .pa-baseline-details summary { cursor: pointer; color: #ccc; font-size: 14px; font-weight: 600; user-select: none; }
  .pa-baseline-policy { margin: 10px 0 8px; line-height: 1.55; }
  .pa-baseline-block { margin-top: 8px; }
  .pa-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .pa-table th { text-align: left; padding: 8px 10px; background: #252525; color: #888; }
  .pa-table td { padding: 8px 10px; color: #ddd; border-top: 1px solid #2a2a2a; }
  .pa-baseline-table td:first-child { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
  .pa-baseline-table tr.pa-baseline-primary td { background: rgba(34, 197, 94, 0.06); }
  .pa-model-badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    color: #0d1f12; background: linear-gradient(90deg, #4ade80, #22c55e);
  }
  .pa-tag { display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 11px; font-weight: 600; }
  .pa-tag.good { background: rgba(52,199,89,0.2); color: #34c759; }
  .pa-tag.bad { background: rgba(255,59,48,0.2); color: #ff6b6b; }
  .pa-tag.muted { background: #333; color: #888; font-weight: 400; }
  .pa-protocol-tags.readonly .pa-tag-btn.readonly { cursor: default; pointer-events: none; padding: 2px 8px; font-size: 11px; }
  .pa-protocol-tags { display: flex; flex-wrap: wrap; gap: 4px; }
  .pa-tag-btn.on { border-color: rgba(171, 8, 227, 0.6); color: #e8d0f5; background: rgba(171, 8, 227, 0.15); padding: 2px 8px; border-radius: 6px; font-size: 11px; }
  .pa-sub-block { margin-top: 18px; }
  .pa-sub-block h3 { color: #ddd; font-size: 14px; margin: 0 0 10px; }
  .pa-cm-table th, .pa-cm-table td { text-align: center; }
  .pa-importance-list { list-style: none; margin: 0; padding: 0; }
  .pa-importance-list li { display: grid; grid-template-columns: 120px 1fr 52px; gap: 10px; align-items: center; margin-bottom: 8px; font-size: 12px; color: #ccc; }
  .pa-imp-bar { height: 6px; background: #2a2a2a; border-radius: 999px; overflow: hidden; }
  .pa-imp-fill { height: 100%; background: linear-gradient(90deg, var(--primary), var(--primary-light)); }
  .pa-importance-list .num { text-align: right; color: #aaa; font-variant-numeric: tabular-nums; }
  .pa-run-sample-detail { margin: 0 0 16px; line-height: 1.55; }
  .pa-sample-source-title { margin: 0 0 10px; font-size: 14px; color: #ddd; font-weight: 600; }
  .pa-sample-source-table { margin-bottom: 10px; font-size: 12px; }
  .pa-sample-total-row th, .pa-sample-total-row td { border-top: 1px solid #444; color: #ddd; }
  .pa-sample-split-line { margin: 0 0 4px; line-height: 1.55; }
  .pa-merged-sessions-block { margin: 16px 0 12px; }
`
