import Icon from './Icon'
import { formatUtcTime } from '../api'

export function runMergeModeInfo(run) {
  const extraPcaps = (run?.extra_good_pcaps ?? 0) + (run?.extra_bad_pcaps ?? 0)
  const mergedCount =
    run?.merged_sessions?.length ?? run?.merged_session_ids?.length ?? extraPcaps ?? 0

  if (run?.include_labeled_captures === false || extraPcaps === 0) {
    return {
      text: '仅本地',
      variant: 'local',
      title: '未合并训练池 pcap，仅使用 goodx/badx',
    }
  }

  return {
    text: mergedCount > 0 ? `已选·${mergedCount}` : '已选 pcap',
    variant: 'pool',
    title: `本次训练合并训练池中 ${mergedCount} 个标注 pcap`,
  }
}

function RunSampleDetail({ run }) {
  const hasSource =
    run?.local_normal_flows != null ||
    run?.local_malicious_flows != null ||
    (run?.extra_normal_flows ?? 0) > 0 ||
    (run?.extra_malicious_flows ?? 0) > 0

  if (run?.sample_total == null && !hasSource) {
    return (
      <p className="muted small pa-run-sample-detail">样本来源未记录（请重新训练后可在详情中查看）</p>
    )
  }

  const localNormal = run.local_normal_flows ?? (hasSource ? 0 : run.sample_normal)
  const localMalicious = run.local_malicious_flows ?? (hasSource ? 0 : run.sample_malicious)
  const extraNormalPcaps = run.extra_good_pcaps ?? 0
  const extraMaliciousPcaps = run.extra_bad_pcaps ?? 0
  const extraNormalFlows = run.extra_normal_flows ?? 0
  const extraMaliciousFlows = run.extra_malicious_flows ?? 0
  const extraNormalPackets = run.extra_normal_packets ?? 0
  const extraMaliciousPackets = run.extra_malicious_packets ?? 0
  const extraPcapTotal = extraNormalPcaps + extraMaliciousPcaps
  const mergedSessions = run.merged_sessions || []
  const showMergedBlock = mergedSessions.length > 0 || extraPcapTotal > 0

  return (
    <div className="pa-run-sample-detail">
      <h3 className="pa-sample-source-title">训练样本来源</h3>
      <table className="pa-table pa-sample-source-table">
        <thead>
          <tr>
            <th>来源</th>
            <th>pcap 份数</th>
            <th>包数</th>
            <th>正常流</th>
            <th>恶意流</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th>本地默认集（goodx/badx）</th>
            <td>—</td>
            <td>—</td>
            <td>{localNormal ?? '—'}</td>
            <td>{localMalicious ?? '—'}</td>
          </tr>
          <tr>
            <th>外来标注 pcap</th>
            <td>
              正常 {extraNormalPcaps} / 恶意 {extraMaliciousPcaps}
            </td>
            <td>
              正常 {extraNormalPackets} / 恶意 {extraMaliciousPackets}
            </td>
            <td>{extraNormalFlows}</td>
            <td>{extraMaliciousFlows}</td>
          </tr>
          <tr className="pa-sample-total-row">
            <th>合计（流级）</th>
            <td colSpan={2} className="muted">
              共 {run.sample_total ?? '—'} 条流
            </td>
            <td>{run.sample_normal ?? '—'}</td>
            <td>{run.sample_malicious ?? '—'}</td>
          </tr>
        </tbody>
      </table>
      {showMergedBlock && (
        <div className="pa-merged-sessions-block">
          <h3 className="pa-sample-source-title">本次合并的标注会话</h3>
          {mergedSessions.length > 0 ? (
            <table className="pa-table pa-merged-sessions-table">
              <thead>
                <tr>
                  <th>文件</th>
                  <th>模式</th>
                  <th>标注</th>
                  <th>协议标签</th>
                  <th>包数</th>
                  <th>流数</th>
                </tr>
              </thead>
              <tbody>
                {mergedSessions.map((s) => (
                  <tr key={s.session_id}>
                    <td className="fname-cell" title={s.filename}>
                      {s.filename}
                    </td>
                    <td>{s.mode_label || '—'}</td>
                    <td>
                      {!s.annotation && <span className="pa-tag muted">—</span>}
                      {s.annotation === 'normal' && <span className="pa-tag good">正常样本</span>}
                      {s.annotation === 'malicious' && <span className="pa-tag bad">恶意样本</span>}
                    </td>
                    <td className="pa-tag-cell">
                      {s.protocol_tags?.length ? (
                        <div className="pa-protocol-tags readonly">
                          {s.protocol_tags.map((tag) => (
                            <span key={tag} className="pa-tag-btn on readonly">
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="muted small">—</span>
                      )}
                    </td>
                    <td>{s.packet_count ?? '—'}</td>
                    <td>{s.flow_count ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="muted small pa-merged-sessions-empty">
              本条记录未保存合并明细（多为旧版训练产生）。请<strong>重启后端</strong>后重新点一次「开始重训」，即可在此看到文件名与协议标签。
            </p>
          )}
        </div>
      )}
      <p className="muted small pa-sample-split-line">
        按 7:3 划分后，<strong>拟合 {run.train_set_size ?? '—'} 条</strong>
        （正常 {run.train_set_normal ?? '—'} / 恶意 {run.train_set_malicious ?? '—'}），
        <strong>测试 {run.test_set_size ?? '—'} 条</strong>
        （正常 {run.test_set_normal ?? '—'} / 恶意 {run.test_set_malicious ?? '—'}）。
      </p>
    </div>
  )
}

export function TrainMetricsPanel({ run, title = '训练评估' }) {
  if (!run) return null
  const algo = run.model_algorithm_label || run.model_algorithm || '随机森林'
  const timeLabel = run.created_at ? formatUtcTime(run.created_at) : null

  return (
    <section className="pa-panel metrics-panel">
      <h2>
        <Icon name="chart" size={20} /> {title}
      </h2>
      <p className="muted small pa-metrics-subtitle">
        {algo}
        {timeLabel ? ` · ${timeLabel}` : ''}
        {run.is_active ? ' · 当前线上模型' : ''}
      </p>
      <RunSampleDetail run={run} />
      <div className="pa-metrics-grid">
        {run.sample_total != null && (
          <>
            <div className="pa-metric-card">
              <span className="label">训练样本（流级）</span>
              <strong>{run.sample_total}</strong>
            </div>
            <div className="pa-metric-card">
              <span className="label">拟合 / 测试划分</span>
              <strong>
                {run.train_set_size ?? '—'} / {run.test_set_size ?? '—'}
              </strong>
            </div>
          </>
        )}
        <div className="pa-metric-card">
          <span className="label">测试准确率</span>
          <strong>{run.test_score != null ? `${(run.test_score * 100).toFixed(2)}%` : '—'}</strong>
        </div>
        <div className="pa-metric-card">
          <span className="label">恶意 Recall</span>
          <strong>
            {run.malicious_recall != null ? `${(run.malicious_recall * 100).toFixed(2)}%` : '—'}
          </strong>
        </div>
        <div className="pa-metric-card">
          <span className="label">恶意 F1</span>
          <strong>{run.malicious_f1 != null ? `${(run.malicious_f1 * 100).toFixed(2)}%` : '—'}</strong>
        </div>
      </div>
      <p className="muted small pa-metrics-rf-hint">
        上方为<strong>随机森林</strong>在<strong>测试集</strong>上的指标，与下表「随机森林」行的测试准确率 / Recall / F1 一致；
        下表多出的「训练准确率」是拟合集表现，通常高于测试集。
      </p>

      <details className="pa-baseline-details">
        <summary>论文用：算法对比（可选，点击展开）</summary>
        <div className="pa-sub-block pa-baseline-block">
          <p className="muted small pa-baseline-policy">
            对比使用<strong>该次重训当时</strong>的样本（goodx/badx + 当时纳入的标注 pcap），不是当前训练池。
            线上固定为<strong>随机森林</strong>，其它算法仅作论文参考，不自动替换。
          </p>
          {run.baseline_comparison?.models?.length > 0 ? (
            <>
              {run.baseline_comparison.training_data_note && (
                <p className="muted small">
                  对比样本：<strong>{run.baseline_comparison.training_data_note}</strong>
                </p>
              )}
              <p className="muted small">{run.baseline_comparison.description}</p>
              <table className="pa-table pa-baseline-table">
                <thead>
                  <tr>
                    <th>算法</th>
                    <th>训练准确率</th>
                    <th>测试准确率</th>
                    <th>恶意 Recall</th>
                    <th>恶意 F1</th>
                  </tr>
                </thead>
                <tbody>
                  {run.baseline_comparison.models.map((m) => (
                    <tr key={m.name} className={m.is_primary ? 'pa-baseline-primary' : undefined}>
                      <td>
                        <span>{m.label || m.name}</span>
                        {m.is_primary && <span className="pa-model-badge">线上</span>}
                      </td>
                      <td>{m.train_score != null ? `${(m.train_score * 100).toFixed(2)}%` : '—'}</td>
                      <td>{m.test_score != null ? `${(m.test_score * 100).toFixed(2)}%` : '—'}</td>
                      <td>
                        {m.malicious_recall != null ? `${(m.malicious_recall * 100).toFixed(2)}%` : '—'}
                      </td>
                      <td>{m.malicious_f1 != null ? `${(m.malicious_f1 * 100).toFixed(2)}%` : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <p className="muted small">
              正在计算或未生成算法对比。可忽略；上方指标卡片即为本次线上模型结果。
            </p>
          )}
        </div>
      </details>

      {run.confusion_matrix?.matrix && (
        <div className="pa-cm-block">
          <h3>混淆矩阵（测试集 · 随机森林）</h3>
          <p className="muted small">{run.confusion_matrix.description}</p>
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
                <td>{run.confusion_matrix.matrix[0]?.[0]}</td>
                <td>{run.confusion_matrix.matrix[0]?.[1]}</td>
              </tr>
              <tr>
                <th>真实安全</th>
                <td>{run.confusion_matrix.matrix[1]?.[0]}</td>
                <td>{run.confusion_matrix.matrix[1]?.[1]}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {run.feature_importance?.length > 0 && (
        <div className="pa-sub-block">
          <h3>特征重要性（{algo} Top）</h3>
          <ul className="pa-importance-list">
            {run.feature_importance.map((f) => (
              <li key={f.name}>
                <span>{f.name}</span>
                <div className="pa-imp-bar">
                  <div
                    className="pa-imp-fill"
                    style={{
                      width: `${Math.min(100, (f.importance / (run.feature_importance[0]?.importance || 1)) * 100)}%`,
                    }}
                  />
                </div>
                <span className="num">{(f.importance * 100).toFixed(2)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
