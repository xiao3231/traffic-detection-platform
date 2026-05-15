/**
 * 接口地址：开发环境用相对路径 `/api/...`，由 Vite 代理到 Flask，避免误打到本机 5000 上的非 Flask 服务（如 macOS AirPlay）拿到 HTML。
 * 生产或独立部署前端时，在 .env 设置 VITE_API_BASE=http://你的后端:端口（不要末尾斜杠）
 */
export function apiUrl(path) {
  const base = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')
  const p = path.startsWith('/') ? path : `/${path}`
  return base ? `${base}${p}` : p
}

/** 解析 JSON；若响应体是 HTML（如 404 页面），抛出可读错误 */
export async function readJsonResponse(res) {
  const text = await res.text()
  const trimmed = text.trim()
  if (!trimmed) return {}
  if (trimmed.startsWith('<')) {
    throw new Error(
      `接口返回了网页而不是 JSON（HTTP ${res.status}）。请确认：1）Flask 已启动；2）已配置 Vite 代理 /api；3）若仍异常，可尝试将后端改为其他端口并在 .env 设置 VITE_API_BASE。`
    )
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`接口返回内容无法解析为 JSON（HTTP ${res.status}）`)
  }
}
