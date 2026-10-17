export type DataMode = 'LIVE' | 'REPLAY';
export type RecordRow = Record<string, any>;
let csrf = '';
export const setCsrf = (value: string) => { csrf = value; };
export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }
export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch('/api' + path, { credentials: 'same-origin', ...options, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...options.headers } });
  if (!response.ok) {
    let detail = response.statusText;
    try { const body = await response.json(); detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail); } catch { /* retain HTTP message */ }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}
export const post = <T = any>(path: string, body: unknown = {}) => api<T>(path, { method: 'POST', body: JSON.stringify(body) });
export const patch = (path: string, body: unknown) => api(path, { method: 'PATCH', body: JSON.stringify(body) });
export const time = (value: string | undefined) => value ? new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
export const dateTime = (value: string | undefined) => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—';
export const words = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, x => x.toUpperCase());
export const number = (value: number = 0) => new Intl.NumberFormat().format(value);
