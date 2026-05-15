import { useState, useRef, useEffect } from 'react'
import Header from '../components/Header'
import Icon from '../components/Icon'
import { apiUrl, readJsonResponse } from '../api'
import './Detection.css'

export default function Detection() {
  const [file, setFile] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const [status, setStatus] = useState('idle') // idle, uploading, analyzing, complete
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const fileInputRef = useRef(null)

  // 模拟检测进度
  useEffect(() => {
    if (status === 'analyzing') {
      const interval = setInterval(() => {
        setProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval)
            return 100
          }
          return prev + Math.random() * 15
        })
      }, 300)
      return () => clearInterval(interval)
    }
  }, [status])

  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile && droppedFile.name.endsWith('.pcap')) {
      setFile(droppedFile)
    }
  }

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0]
    if (selectedFile) {
      setFile(selectedFile)
    }
  }

  const handleUpload = async () => {
    if (!file) return
    
    setStatus('uploading')
    setProgress(0)
    setResult(null)
    
    const formData = new FormData()
    formData.append('file', file)
    
    try {
      setStatus('analyzing')
      const response = await fetch(apiUrl('/api/detection'), {
        method: 'POST',
        credentials: 'include',
        body: formData
      })
      
      const data = await readJsonResponse(response)
      
      if (response.ok) {
        const pr = data.protocols || {}
        setResult({
          status: data.result === '安全' ? 'safe' : 'danger',
          message: data.result,
          time: data.elapsed_time,
          packets: data.total_packets,
          protocols: {
            TCP: pr.TCP ?? 0,
            UDP: pr.UDP ?? 0,
            ICMP: pr.ICMP ?? 0,
            ARP: pr.ARP ?? 0,
            HTTP: pr.HTTP ?? 0,
            Other: pr.Other ?? 0,
          },
        })
        
        // 添加到历史记录
        setHistory(prev => [{
          id: Date.now(),
          name: file.name,
          result: data.result,
          time: new Date().toLocaleString()
        }, ...prev].slice(0, 5))
        
        setStatus('complete')
        setProgress(100)
      } else {
        setStatus('idle')
        alert(data.error || '检测失败')
      }
    } catch (error) {
      setStatus('idle')
      alert('网络错误，请重试')
    }
  }

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  return (
    <div className="detection-page">
      <Header />
      
      <div className="detection-content">
        <header className="det-page-head">
          <h1>流量检测</h1>
          <p>上传 pcap 后由服务端提取特征并调用已训练模型给出安全 / 危险结论，右侧可查看协议占比与耗时。</p>
        </header>

        <div className="stats-row">
          <div className="stat-card">
            <Icon name="file" size={32} className="stat-icon" />
            <div className="stat-info">
              <span className="stat-value">{history.length}</span>
              <span className="stat-label">检测次数</span>
            </div>
          </div>
          <div className="stat-card">
            <Icon name="safe" size={32} className="stat-icon safe" />
            <div className="stat-info">
              <span className="stat-value">{history.filter(h => h.result === '安全').length}</span>
              <span className="stat-label">安全文件</span>
            </div>
          </div>
          <div className="stat-card">
            <Icon name="danger" size={32} className="stat-icon danger" />
            <div className="stat-info">
              <span className="stat-value">{history.filter(h => h.result !== '安全').length}</span>
              <span className="stat-label">危险文件</span>
            </div>
          </div>
        </div>

        <div className="main-row">
          <section className="upload-section det-panel">
            <div className="det-section-head">
              <h2>上传与检测</h2>
              <span>仅 .pcap</span>
            </div>

            <div
              role="button"
              tabIndex={0}
              className={`drop-zone ${isDragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  fileInputRef.current?.click()
                }
              }}
            >
              <input 
                type="file" 
                ref={fileInputRef}
                accept=".pcap"
                onChange={handleFileSelect}
                style={{ display: 'none' }}
              />
              
              {!file ? (
                <>
                  <Icon name="uploadCloud" size={64} className="upload-icon" />
                  <p className="drop-text">拖放 pcap 文件到此处</p>
                  <p className="drop-hint">或点击选择文件</p>
                  <span className="file-format">支持 .pcap 格式，最大 10MB</span>
                </>
              ) : (
                <div className="file-preview">
                  <Icon name="filePcap" size={48} className="file-icon" />
                  <div className="file-info">
                    <span className="file-name">{file.name}</span>
                    <span className="file-size">{formatFileSize(file.size)}</span>
                  </div>
                  <button 
                    className="remove-btn"
                    onClick={(e) => {
                      e.stopPropagation()
                      setFile(null)
                      setStatus('idle')
                      setResult(null)
                      setProgress(0)
                    }}
                  >
                    <Icon name="close" size={20} />
                  </button>
                </div>
              )}
            </div>

            {/* 检测按钮 */}
            <button 
              className="detect-btn"
              disabled={!file || status === 'uploading' || status === 'analyzing'}
              onClick={handleUpload}
            >
              {status === 'uploading' || status === 'analyzing' ? (
                <>
                  <Icon name="loading" size={20} className="spinning" />
                  检测中...
                </>
              ) : (
                <>
                  <Icon name="scan" size={20} />
                  开始检测
                </>
              )}
            </button>

            {/* 进度条 */}
            {(status === 'uploading' || status === 'analyzing') && (
              <div className="progress-section">
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${Math.min(progress, 100)}%` }}></div>
                </div>
                <span className="progress-text">
                  {status === 'uploading' ? '上传中...' : '分析中...'}
                </span>
              </div>
            )}
          </section>

          <section className="result-section det-panel">
            <div className="det-section-head">
              <h2>检测结果</h2>
              <span>实时来自接口</span>
            </div>
            
            {result ? (
              <div className={`result-card ${result.status}`}>
                <div className="result-icon">
                  <Icon 
                    name={result.status === 'safe' ? 'shieldCheck' : 'shieldWarning'} 
                    size={80} 
                  />
                </div>
                <div className="result-status">
                  {result.status === 'safe' ? '检测通过' : '存在风险'}
                </div>
                <div className={`result-badge ${result.status}`}>
                  {result.message}
                </div>
                
                <div className="det-chip-row">
                  <div className="det-chip">
                    <Icon name="chart" size={18} />
                    <span>耗时</span>
                    <strong>{result.time}s</strong>
                  </div>
                  <div className="det-chip">
                    <Icon name="file" size={18} />
                    <span>数据包</span>
                    <strong>{Number(result.packets || 0).toLocaleString()}</strong>
                  </div>
                </div>

                <div className="protocol-stats">
                  <h4>协议分布</h4>
                  {result.protocols.TCP > 0 && (
                    <div className="protocol-item">
                      <span>TCP</span>
                      <div className="protocol-bar">
                        <div className="protocol-fill" style={{ width: `${result.packets > 0 ? (result.protocols.TCP / result.packets) * 100 : 0}%` }}></div>
                      </div>
                      <span>{result.protocols.TCP}</span>
                    </div>
                  )}
                  {result.protocols.UDP > 0 && (
                    <div className="protocol-item">
                      <span>UDP</span>
                      <div className="protocol-bar">
                        <div className="protocol-fill" style={{ width: `${result.packets > 0 ? (result.protocols.UDP / result.packets) * 100 : 0}%` }}></div>
                      </div>
                      <span>{result.protocols.UDP}</span>
                    </div>
                  )}
                  {result.protocols.ICMP > 0 && (
                    <div className="protocol-item">
                      <span>ICMP</span>
                      <div className="protocol-bar">
                        <div className="protocol-fill" style={{ width: `${result.packets > 0 ? (result.protocols.ICMP / result.packets) * 100 : 0}%` }}></div>
                      </div>
                      <span>{result.protocols.ICMP}</span>
                    </div>
                  )}
                  {result.protocols.ARP > 0 && (
                    <div className="protocol-item">
                      <span>ARP</span>
                      <div className="protocol-bar">
                        <div className="protocol-fill" style={{ width: `${result.packets > 0 ? (result.protocols.ARP / result.packets) * 100 : 0}%` }}></div>
                      </div>
                      <span>{result.protocols.ARP}</span>
                    </div>
                  )}
                  {result.protocols.HTTP > 0 && (
                    <div className="protocol-item">
                      <span>HTTP</span>
                      <div className="protocol-bar">
                        <div className="protocol-fill" style={{ width: `${result.packets > 0 ? (result.protocols.HTTP / result.packets) * 100 : 0}%` }}></div>
                      </div>
                      <span>{result.protocols.HTTP}</span>
                    </div>
                  )}
                  {result.protocols.Other > 0 && (
                    <div className="protocol-item">
                      <span>Other</span>
                      <div className="protocol-bar">
                        <div className="protocol-fill" style={{ width: `${result.packets > 0 ? (result.protocols.Other / result.packets) * 100 : 0}%` }}></div>
                      </div>
                      <span>{result.protocols.Other}</span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="result-empty">
                <Icon name="info" size={48} />
                <p>请上传 pcap 文件进行检测</p>
              </div>
            )}
          </section>
        </div>

        {history.length > 0 && (
          <section className="history-section">
            <div className="det-section-head">
              <h2>本会话最近检测</h2>
              <span>刷新页面后清空</span>
            </div>
            <div className="history-list">
              {history.map(item => (
                <div key={item.id} className="history-item">
                  <Icon name="filePcap" size={24} />
                  <div className="history-info">
                    <span className="history-name">{item.name}</span>
                    <span className="history-time">{item.time}</span>
                  </div>
                  <span className={`history-result ${item.result === '安全' ? 'safe' : 'danger'}`}>
                    {item.result}
                  </span>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
