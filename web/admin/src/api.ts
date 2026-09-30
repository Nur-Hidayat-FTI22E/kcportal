// Typed client for the §7.2 REST admin API. The bearer token lives in
// localStorage (per browser, per device) — same origin, so no CORS.

const TOKEN_KEY = "kcp_admin_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(tok: string) {
  localStorage.setItem(TOKEN_KEY, tok);
}

export function hasToken(): boolean {
  return getToken().length > 0;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = (data as { error?: string }).error ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => call<T>("GET", path),
  post: <T>(path: string, body: unknown) => call<T>("POST", path, body),
  put: <T>(path: string, body: unknown) => call<T>("PUT", path, body),
  del: <T>(path: string) => call<T>("DELETE", path),
};

// --- response shapes (mirrors internal/api handlers) ---

export interface Device {
  MAC: string;
  State: string;
  Hostname: string;
  Zone: string;
  IP: string;
  LastSeen: string;
}

export interface Guest {
  MAC: string;
  IP: string;
  StartedAt: string;
  ExpiresAt: string;
  Marketing: boolean;
}

export interface Zone {
  ID: number;
  Name: string;
  Subnet: string;
  Internet: boolean;
  VPNPolicy: string;
  LANAllow: string;
  Isolate: boolean;
  BWKbps: number | null;
}

export interface Voucher {
  Code: string;
  DurationSec: number;
  MaxUses: number;
  Used: number;
  ExpiresAt: string;
  CreatedAt: string;
}

export interface AuditEntry {
  ID: number;
  Ts: string;
  Actor: string;
  Action: string;
  Target: string;
  Diff: string;
}

export interface WanPosture {
  wan?: { mode: string; iface?: string };
  iface?: string;
  iface_addr?: string;
  uplink: { ok: boolean; detail?: string };
  bridges: Record<string, boolean>;
  bridges_ready: boolean;
}

export interface ShieldStats {
  Installed: boolean;
  DoHPackets: number;
  DoTPackets: number;
  DoQPackets: number;
}

export const endpoints = {
  devices: (state?: string) =>
    `/api/v1/devices${state ? `?state=${encodeURIComponent(state)}` : ""}`,
  approveDevice: "/api/v1/devices/approve",
  blockDevice: "/api/v1/devices/block",
  guests: "/api/v1/guests",
  revokeGuest: "/api/v1/guests/revoke",
  zones: "/api/v1/zones",
  zonePolicy: (id: number) => `/api/v1/zones/${id}/policy`,
  pending: "/api/v1/changes/pending",
  confirm: "/api/v1/changes/confirm",
  audit: (limit = 100) => `/api/v1/audit?limit=${limit}`,
  vouchers: "/api/v1/vouchers",
  deleteVoucher: (code: string) => `/api/v1/vouchers/${encodeURIComponent(code)}`,
  wan: "/api/v1/network/wan",
  doh: "/api/v1/network/doh",
};
