// Shared API client and response types for the console.

export interface User {
  id: number;
  username: string;
  role: 'admin' | 'viewer' | string;
  disabled?: boolean;
  created_at?: string;
  updated_at?: string;
  last_login?: string;
}

export interface SetupStatus {
  needs_setup: boolean;
  allow_registration: boolean;
  registration_open: boolean;
}

export interface QueryLog {
  ts: string;
  method: string;
  path: string;
  ip: string;
  connection_type: string;
  country: string;
}

export interface Stats {
  users: number;
  queries_total: number;
  queries_today: number;
}

export interface Provider {
  name: string;
  kind: string;
  enabled: boolean;
  priority: number;
  url?: string;
  headers?: Record<string, string>;
  path?: string;
  command?: string;
  format?: string;
  refresh_min?: number;
  builtin: boolean;
  status: string;
  error?: string;
  entries: number;
  observations: number;
  source?: string;
  exported?: string;
  last_sync?: string;
  loaded_at?: string;
}

export interface Dataset {
  name: string;
  description: string;
  providers: Provider[];
}

export interface IPProvider {
  name: string;
  kind: string;
  driver?: string;
  enabled: boolean;
  priority: number;
  url?: string;
  headers?: Record<string, string>;
  mapping?: Record<string, string>;
  command?: string;
  timeout_sec?: number;
  builtin: boolean;
  status: string;
  gated?: boolean;
  last_error?: string;
  calls: number;
  successes: number;
  failures: number;
  avg_ms: number;
  last_success?: string;
}

export type Config = Record<string, string>;

export interface SystemInfo {
  version: string;
  build_commit?: string;
  build_date?: string;
  go_version: string;
  os: string;
  arch: string;
  cpus: number;
  started_at: string;
  uptime_seconds: number;
  goroutines: number;
  memory_alloc: number;
  memory_sys: number;
  gc_cycles: number;
  db_path: string;
  db_size: number;
  https_port: string;
  http_port: string;
  maintenance: boolean;
  jwt_secret_env: boolean;
  stats: Stats;
}

export interface Bucket {
  label: string;
  count: number;
}

export interface MetricsSummary {
  hours: number;
  since: string;
  total: number;
  unique_ips: number;
  by_hour: { hour: string; count: number }[];
  top_ips: Bucket[];
  top_countries: Bucket[];
  top_methods: Bucket[];
  by_connection: Bucket[];
}

export interface AuditEntry {
  id: number;
  ts: string;
  username: string;
  action: string;
  target: string;
  detail: string;
  ip: string;
}

export interface NotificationItem {
  id: number;
  ts: string;
  level: 'info' | 'warning' | 'error' | string;
  title: string;
  body: string;
  source: string;
  read: boolean;
}

export interface APIKey {
  id: number;
  name: string;
  prefix: string;
  scope: string;
  enabled: boolean;
  created_at: string;
  last_used: string;
  expires_at: string;
}

export interface Webhook {
  id: number;
  name: string;
  url: string;
  events: string;
  enabled: boolean;
  created_at: string;
  last_status: string;
  last_sent: string;
}

export interface JA4StatProvider {
  name: string;
  entries: number;
  observations: number;
  source?: string;
  exported?: string;
  generated?: string;
}

export interface JA4Hit {
  ja4: string;
  provider: string;
  name?: string;
  family?: string;
  version?: string;
  confidence: number;
  observations: number;
  verified: boolean;
  clients: { name: string; family?: string; share: number }[];
}

export interface SavedView {
  id: number;
  name: string;
  page: string;
  filters: string;
  username: string;
  created_at: string;
}

export interface EndpointDoc {
  method: string;
  path: string;
  summary: string;
  group: string;
  auth: string;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function api<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
    ...((init?.headers as Record<string, string> | undefined) || {}),
  };
  if (token) headers.Authorization = 'Bearer ' + token;

  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    const text = (await res.text()).trim();
    throw new ApiError(res.status, text || res.statusText || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const getJSON = <T,>(path: string, token: string) => api<T>(path, token);

export const postJSON = <T,>(path: string, token: string, body: unknown) =>
  api<T>(path, token, { method: 'POST', body: JSON.stringify(body) });

export const deleteJSON = <T = void,>(path: string, token: string) =>
  api<T>(path, token, { method: 'DELETE' });

export function errorText(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}

export function fmtTime(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('zh-CN', { hour12: false });
}

// downloadFile streams an authenticated endpoint (CSV/JSON/backup) to disk.
export async function downloadFile(path: string, token: string, fallbackName = 'download'): Promise<void> {
  const res = await fetch(path, { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) {
    throw new ApiError(res.status, (await res.text()).trim() || res.statusText);
  }
  const blob = await res.blob();
  const cd = res.headers.get('Content-Disposition') || '';
  const match = /filename="?([^";]+)"?/.exec(cd);
  const name = match ? match[1] : fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function fmtBytes(n?: number): string {
  if (!n || n < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtDuration(seconds?: number): string {
  if (!seconds || seconds < 0) return '0 秒';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d) return `${d} 天 ${h} 小时`;
  if (h) return `${h} 小时 ${m} 分`;
  if (m) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

export function shortTime(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' }) + ' ' +
    d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit' });
}
