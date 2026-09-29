import { useEffect, useState } from "react";
import { api, ApiError, newIdempotencyKey, rupiah } from "./api";

interface Product {
  id: number;
  name: string;
  price: number;
}
interface CartLine {
  product: Product;
  qty: number;
}
type Me = { id: number; name: string; role: string };

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe(null)).finally(() => setBooting(false));
  }, []);

  if (booting) return <div className="center muted">Memuat…</div>;
  if (!me) return <Login onLogin={setMe} />;
  return <Cashier me={me} onLogout={() => setMe(null)} />;
}

function Login({ onLogin }: { onLogin: (me: Me) => void }) {
  const [name, setName] = useState("");
  const [pin, setPin] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.login(name, pin);
      onLogin(await api.me());
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : "login gagal");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>KotaCloud Kasir</h1>
        <input placeholder="nama kasir" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        <input
          placeholder="PIN"
          type="password"
          inputMode="numeric"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
        />
        {err && <p className="warn">{err}</p>}
        <button disabled={busy || !name || !pin}>{busy ? "…" : "Masuk"}</button>
      </form>
    </div>
  );
}

function Cashier({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [shiftOpen, setShiftOpen] = useState<boolean | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [cart, setCart] = useState<CartLine[]>([]);
  const [msg, setMsg] = useState("");
  const [payModal, setPayModal] = useState(false);
  const [closeModal, setCloseModal] = useState(false);

  const loadProducts = () => api.products().then((r) => setProducts(r.products));
  useEffect(() => {
    loadProducts().catch(() => setMsg("gagal memuat katalog"));
    // Shift state is implicit: opening fails with 409 when one is open.
    // We probe by listing products only; the OpenShift bar shows until
    // an open succeeds, then hides for the session.
  }, []);

  const total = cart.reduce((s, l) => s + l.product.price * l.qty, 0);

  const add = (p: Product) => {
    setCart((c) => {
      const i = c.findIndex((l) => l.product.id === p.id);
      if (i >= 0) {
        const next = [...c];
        next[i] = { ...next[i], qty: next[i].qty + 1 };
        return next;
      }
      return [...c, { product: p, qty: 1 }];
    });
  };
  const dec = (id: number) =>
    setCart((c) =>
      c.flatMap((l) => (l.product.id === id ? (l.qty > 1 ? [{ ...l, qty: l.qty - 1 }] : []) : [l])),
    );

  if (shiftOpen === null) {
    return (
      <div className="app">
        <Header me={me} onLogout={onLogout} />
        <div className="card" style={{ marginTop: 14 }}>
          <h2>Buka shift</h2>
          <OpenShiftForm
            onOpen={async () => {
              setShiftOpen(true);
              await loadProducts();
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <Header me={me} onLogout={onLogout} />
      {msg && <div className="banner warn">{msg}</div>}
      <main className="cols">
        <div className="card">
          <h2>Katalog</h2>
          <div className="grid">
            {products.map((p) => (
              <button key={p.id} className="prod" onClick={() => add(p)}>
                <span>{p.name}</span>
                <b className="muted">{rupiah(p.price)}</b>
              </button>
            ))}
            {products.length === 0 && <p className="muted">Katalog kosong.</p>}
          </div>
        </div>
        <div className="card">
          <h2>Order</h2>
          {cart.length === 0 && <p className="muted">Ketuk produk untuk menambah.</p>}
          <table>
            <tbody>
              {cart.map((l) => (
                <tr key={l.product.id}>
                  <td>{l.product.name}</td>
                  <td className="num">
                    <button className="small ghost" onClick={() => dec(l.product.id)}>
                      −
                    </button>{" "}
                    {l.qty}{" "}
                    <button className="small ghost" onClick={() => add(l.product)}>
                      +
                    </button>
                  </td>
                  <td className="num" style={{ minWidth: 90 }}>
                    {rupiah(l.product.price * l.qty)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="total">
            <b>Total: Rp {rupiah(total)}</b>
          </p>
          <div className="row">
            <button disabled={cart.length === 0} onClick={() => setPayModal(true)}>
              Bayar
            </button>
            <button className="ghost" disabled={cart.length === 0} onClick={() => setCart([])}>
              Kosongkan
            </button>
            {me.role === "admin" && (
              <button className="ghost" onClick={() => setCloseModal(true)}>
                Tutup shift
              </button>
            )}
          </div>
        </div>
      </main>
      {payModal && (
        <PayModal
          cart={cart}
          total={total}
          onClose={() => setPayModal(false)}
          onPaid={(m) => {
            setMsg(m);
            setCart([]);
            setPayModal(false);
          }}
        />
      )}
      {closeModal && (
        <CloseModal
          onClose={() => setCloseModal(false)}
          onClosed={(m) => {
            setMsg(m);
            setCloseModal(false);
            setShiftOpen(false);
            setCart([]);
          }}
        />
      )}
    </div>
  );
}

function Header({ me, onLogout }: { me: Me; onLogout: () => void }) {
  return (
    <header>
      <h1>KotaCloud Kasir</h1>
      <span className="muted">
        {me.name} · {me.role}
      </span>
      <button
        className="ghost"
        onClick={async () => {
          await api.logout().catch(() => {});
          onLogout();
        }}
      >
        Keluar
      </button>
    </header>
  );
}

function OpenShiftForm({ onOpen }: { onOpen: () => void }) {
  const [cash, setCash] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.openShift(Number(cash || "0"));
      onOpen();
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : "gagal buka shift");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit}>
      <p className="muted">Masukkan modal awal laci (uang fisik yang dihitung).</p>
      <input placeholder="modal awal, mis. 100000" inputMode="numeric" value={cash} onChange={(e) => setCash(e.target.value)} />
      {err && <p className="warn">{err}</p>}
      <button disabled={busy}>{busy ? "…" : "Buka shift"}</button>
    </form>
  );
}

function PayModal({
  cart,
  total,
  onClose,
  onPaid,
}: {
  cart: CartLine[];
  total: number;
  onClose: () => void;
  onPaid: (msg: string) => void;
}) {
  const [method, setMethod] = useState<"cash" | "qris">("cash");
  const [tendered, setTendered] = useState("");
  const [reference, setReference] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const t = Number(tendered || "0");
  const change = method === "cash" ? t - total : 0;

  const submit = async () => {
    setBusy(true);
    setErr("");
    try {
      const table = "";
      const created = await api.createOrder(table);
      for (const l of cart) {
        await api.addItem(created.order_id, l.product.id, l.qty);
      }
      const res = await api.pay(
        created.order_id,
        method,
        total,
        method === "cash" ? t : total,
        reference,
        newIdempotencyKey(),
      );
      onPaid(
        `LUNAS ${created.order_no} — ${method === "cash" ? `kembalian Rp ${rupiah(res.change)}` : "QRIS"} ✔`,
      );
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : "pembayaran gagal");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal" onClick={onClose}>
      <div className="card modalcard" onClick={(e) => e.stopPropagation()}>
        <h2>Bayar — Rp {rupiah(total)}</h2>
        <label className="check">
          <input type="radio" checked={method === "cash"} onChange={() => setMethod("cash")} /> Tunai
        </label>
        <label className="check">
          <input type="radio" checked={method === "qris"} onChange={() => setMethod("qris")} /> QRIS (manual)
        </label>
        {method === "cash" ? (
          <>
            <input placeholder="uang diterima" inputMode="numeric" value={tendered} onChange={(e) => setTendered(e.target.value)} autoFocus />
            <p className={change < 0 ? "warn" : "ok"}>
              Kembalian: Rp {rupiah(Math.max(0, change))}
              {change < 0 && " (kurang)"}
            </p>
          </>
        ) : (
          <input placeholder="referensi QRIS/EDC" value={reference} onChange={(e) => setReference(e.target.value)} autoFocus />
        )}
        {err && <p className="warn">{err}</p>}
        <div className="row">
          <button
            disabled={busy || (method === "cash" && t < total) || (method === "qris" && !reference)}
            onClick={submit}
          >
            {busy ? "…" : "Konfirmasi"}
          </button>
          <button className="ghost" onClick={onClose}>
            Batal
          </button>
        </div>
      </div>
    </div>
  );
}

function CloseModal({ onClose, onClosed }: { onClose: () => void; onClosed: (msg: string) => void }) {
  const [cash, setCash] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api.closeShift(Number(cash || "0"), note);
      const diffTxt = r.diff === 0 ? "pas" : r.diff > 0 ? `lebih ${rupiah(r.diff)}` : `kurang ${rupiah(-r.diff)}`;
      onClosed(`Shift ditutup — selisih: ${diffTxt}`);
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : "gagal tutup shift");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="modal" onClick={onClose}>
      <div className="card modalcard" onClick={(e) => e.stopPropagation()}>
        <h2>Tutup shift</h2>
        <p className="muted">Hitung uang di laci, masukkan jumlahnya.</p>
        <input placeholder="uang terhitung" inputMode="numeric" value={cash} onChange={(e) => setCash(e.target.value)} autoFocus />
        <input placeholder="catatan (opsional)" value={note} onChange={(e) => setNote(e.target.value)} />
        {err && <p className="warn">{err}</p>}
        <div className="row">
          <button disabled={busy} onClick={submit}>
            {busy ? "…" : "Tutup shift"}
          </button>
          <button className="ghost" onClick={onClose}>
            Batal
          </button>
        </div>
      </div>
    </div>
  );
}
