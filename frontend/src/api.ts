// Minimal typed API client. Mutating requests carry X-Sentinel-Client (server-side CSRF guard).

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message)
  }
}

async function request<T>(method: string, url: string, body?: unknown, isForm = false): Promise<T> {
  const headers: Record<string, string> = {}
  if (method !== 'GET') headers['X-Sentinel-Client'] = 'web'
  if (body !== undefined && !isForm) headers['Content-Type'] = 'application/json'
  let res: Response
  try {
    res = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : isForm ? (body as FormData) : JSON.stringify(body),
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError('Cannot reach the SENTINEL-SC backend. Is it running on port 8000?', 0)
  }
  const text = await res.text()
  let data: unknown = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  if (!res.ok) {
    const msg = (data && typeof data === 'object' && 'error' in data) ? String((data as { error: string }).error) : `Request failed (${res.status})`
    throw new ApiError(msg, res.status)
  }
  return data as T
}

export const api = {
  get: <T,>(url: string) => request<T>('GET', url),
  post: <T,>(url: string, body?: unknown) => request<T>('POST', url, body ?? {}),
  put: <T,>(url: string, body: unknown) => request<T>('PUT', url, body),
  del: <T,>(url: string) => request<T>('DELETE', url),
  upload: <T,>(url: string, form: FormData) => request<T>('POST', url, form, true),
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}
