// Client for the pos-cafe JSON API. Session rides an HttpOnly cookie
// set by /api/login — no token storage here.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call<T>(method: string, path: string, body?: unknown, idempotencyKey?: string): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(res.status, (data as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return data as T;
}

export const api = {
  login: (name: string, pin: string) => call<{ ok: true; role: string }>("POST", "/api/login", { name, pin }),
  logout: () => call<{ ok: true }>("POST", "/api/logout"),
  me: () => call<{ id: number; name: string; role: string }>("GET", "/api/me"),
  openShift: (openingCash: number) => call<{ shift_id: number }>("POST", "/api/shift/open", { opening_cash: openingCash }),
  closeShift: (closingCash: number, note: string) =>
    call<{ shift_id: number; expected: number; diff: number }>("POST", "/api/shift/close", { closing_cash: closingCash, note }),
  products: () => call<{ products: { id: number; name: string; price: number }[] }>("GET", "/api/products"),
  createOrder: (table: string) => call<{ order_id: number; order_no: string }>("POST", "/api/orders", { table }),
  addItem: (orderID: number, productID: number, qty: number) =>
    call<{ ok: true }>("POST", `/api/orders/${orderID}/items`, { product_id: productID, qty }),
  pay: (orderID: number, method: string, amount: number, tendered: number, reference: string, key: string) =>
    call<{ payment_id: number; change: number }>(
      "POST",
      `/api/orders/${orderID}/pay`,
      { method, amount, tendered, reference },
      key,
    ),
  voidOrder: (orderID: number, reason: string) =>
    call<{ ok: true }>("POST", `/api/orders/${orderID}/void`, { reason }),
};

export function rupiah(v: number): string {
  return v.toLocaleString("id-ID");
}

export function newIdempotencyKey(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}
