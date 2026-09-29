import { useCallback, useEffect, useState } from "react";
import {
  api,
  endpoints,
  getToken,
  hasToken,
  setToken,
  type Device,
  type Guest,
  type Zone,
  type Voucher,
  type AuditEntry,
  type WanPosture,
} from "./api";

// --- shared bits ---

type Tab = "wizard" | "devices" | "guests" | "vouchers" | "zones" | "audit";

const TABS: { id: Tab; label: string }[] = [
  { id: "wizard", label: "Setup" },
  { id: "devices", label: "Devices" },
  { id: "guests", label: "Tamu" },
  { id: "vouchers", label: "Voucher" },
  { id: "zones", label: "Zona" },
  { id: "audit", label: "Audit" },
];

function Card({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <section className="card">
      {title && <h2>{title}</h2>}
      {children}
    </section>
  );
}

function usePoll<T>(fn: () => Promise<T>, ms: number) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string>("");
  const run = useCallback(() => {
    fn()
      .then((d) => {
        setData(d);
        setErr("");
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
  }, [fn]);
  useEffect(() => {
    run();
    const t = setInterval(run, ms);
    return () => clearInterval(t);
  }, [run, ms]);
  return { data, err, reload: run };
}

function fmtTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("id-ID", { dateStyle: "short", timeStyle: "medium" });
}

function fmtDur(sec: number): string {
  const m = Math.round(sec / 60);
  return m >= 60 ? `${Math.floor(m / 60)} j ${m % 60} m` : `${m} m`;
}

// --- login gate ---

function Login({ onLogin }: { onLogin: () => void }) {
  const [tok, setTok] = useState("");
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setToken(tok.trim());
    onLogin();
  };
  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>kotacloud admin</h1>
        <p>
          Token admin API — tampilkan sekali di Pi dengan{" "}
          <code>kcportald -api-token</code>.
        </p>
        <input
          type="password"
          placeholder="token"
          value={tok}
          onChange={(e) => setTok(e.target.value)}
          autoFocus
        />
        <button type="submit">Masuk</button>
      </form>
    </div>
  );
}

// --- pending banner (commit-confirm, IF-02) ---

function PendingBanner() {
  const { data } = usePoll<{
    pending: boolean;
    deadline?: string;
    change_id?: string;
    risk_reason?: string;
  }>(() => api.get(endpoints.pending), 3000);
  const [left, setLeft] = useState(0);
  useEffect(() => {
    if (!data?.pending || !data.deadline) return;
    const t = setInterval(() => {
      setLeft(Math.max(0, Math.round((new Date(data.deadline!).getTime() - Date.now()) / 1000)));
    }, 500);
    return () => clearInterval(t);
  }, [data]);
  if (!data?.pending) return null;
  const confirm = async () => {
    if (!data.change_id) return;
    try {
      await api.post(endpoints.confirm, { change_id: data.change_id });
      window.location.reload();
    } catch (e) {
      alert(e instanceof Error ? e.message : e);
    }
  };
  return (
    <div className="banner warn">
      <span>
        Perubahan berisiko{data.risk_reason ? ` (${data.risk_reason})` : ""} menunggu
        konfirmasi — rollback otomatis dalam <b>{left}s</b>.
      </span>
      <button onClick={confirm}>Konfirmasi</button>
    </div>
  );
}

// --- wizard tab ---

function WizardTab() {
  const { data, err, reload } = usePoll<WanPosture>(() => api.get(endpoints.wan), 8000);
  const [mode, setMode] = useState("");
  const [iface, setIface] = useState("");
  const [busy, setBusy] = useState(false);
  if (err) return <Card title="Setup jaringan">⚠ {err}</Card>;
  if (!data) return <Card title="Setup jaringan">Memuat…</Card>;
  const post = async () => {
    setBusy(true);
    try {
      await api.post(endpoints.wan, { wan: { mode }, iface });
      await reload();
    } catch (e) {
      alert(e instanceof Error ? e.message : e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Card title="Setup jaringan (WAN)">
        <table>
          <tbody>
            <tr>
              <th>Uplink terdeteksi</th>
              <td>
                <code>{data.iface ?? "—"}</code> {data.iface_addr && `(${data.iface_addr})`}
              </td>
            </tr>
            <tr>
              <th>Internet</th>
              <td>{data.uplink.ok ? "✅ terhubung" : `❌ ${data.uplink.detail ?? "tidak ada rute"}`}</td>
            </tr>
            <tr>
              <th>Bridge</th>
              <td>
                br-lan {data.bridges["br-lan"] ? "✅" : "❌"} · br-guest{" "}
                {data.bridges["br-guest"] ? "✅" : "❌"}
              </td>
            </tr>
            <tr>
              <th>Postur tersimpan</th>
              <td>{data.wan ? `${data.wan.mode}${data.wan.iface ? ` @ ${data.wan.iface}` : ""}` : "belum diatur"}</td>
            </tr>
          </tbody>
        </table>
        <p className="muted">
          Pencatatan di sini <b>tidak mengubah kernel</b> — bridging/migrasi
          uplink tetap lewat <code>kcp-net-apply.sh</code> agar akses manajemen
          tidak terputus (DD-15). Postur berlaku pada boot berikutnya.
        </p>
        <div className="row">
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="">— mode WAN —</option>
            <option value="dhcp">dhcp</option>
            <option value="pppoe">pppoe</option>
            <option value="static">static</option>
          </select>
          <input
            placeholder="iface (mis. eth0)"
            value={iface}
            onChange={(e) => setIface(e.target.value)}
          />
          <button disabled={busy || !mode} onClick={post}>
            Simpan postur
          </button>
        </div>
      </Card>
    </>
  );
}

// --- devices tab ---

function DevicesTab() {
  const [state, setState] = useState("");
  const { data, err, reload } = usePoll<{ devices: Device[] }>(
    () => api.get(endpoints.devices(state || undefined)),
    5000,
  );
  const [mac, setMac] = useState("");
  const [zone, setZone] = useState("3");
  const zones = usePoll<{ zones: Zone[] }>(() => api.get(endpoints.zones), 15000);
  const act = async (path: string, body: unknown) => {
    try {
      await api.post(path, body);
      await reload();
    } catch (e) {
      alert(e instanceof Error ? e.message : e);
    }
  };
  return (
    <>
      <Card title="Setujui perangkat">
        <div className="row">
          <input
            placeholder="MAC (aa:bb:cc:dd:ee:ff)"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
          <select value={zone} onChange={(e) => setZone(e.target.value)}>
            {(zones.data?.zones ?? []).map((z) => (
              <option key={z.ID} value={z.ID}>
                {z.Name}
              </option>
            ))}
          </select>
          <button
            disabled={!mac}
            onClick={() => act(endpoints.approveDevice, { mac, zone_id: Number(zone), note: "web/admin" })}
          >
            Setujui
          </button>
          <button className="danger" disabled={!mac} onClick={() => act(endpoints.blockDevice, { mac })}>
            Blokir
          </button>
        </div>
      </Card>
      <Card title="Perangkat">
        {err && <p>⚠ {err}</p>}
        <div className="row">
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">semua state</option>
            <option value="waiting">waiting</option>
            <option value="approved">approved</option>
            <option value="blocked">blocked</option>
          </select>
        </div>
        <table>
          <thead>
            <tr>
              <th>MAC</th>
              <th>Hostname</th>
              <th>State</th>
              <th>Zona</th>
              <th>IP</th>
              <th>Terakhir terlihat</th>
            </tr>
          </thead>
          <tbody>
            {(data?.devices ?? []).map((d) => (
              <tr key={d.MAC}>
                <td>
                  <code>{d.MAC}</code>
                </td>
                <td>{d.Hostname || "—"}</td>
                <td>
                  <span className={`pill ${d.State}`}>{d.State || "?"}</span>
                </td>
                <td>{d.Zone || "—"}</td>
                <td>{d.IP || "—"}</td>
                <td>{fmtTime(d.LastSeen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(data?.devices ?? []).length === 0 && <p className="muted">Belum ada perangkat.</p>}
      </Card>
    </>
  );
}

// --- guests tab ---

function GuestsTab() {
  const { data, err, reload } = usePoll<{ guests: Guest[] }>(() => api.get(endpoints.guests), 4000);
  const revoke = async (mac: string) => {
    try {
      await api.post(endpoints.revokeGuest, { mac });
      await reload();
    } catch (e) {
      alert(e instanceof Error ? e.message : e);
    }
  };
  return (
    <Card title="Sesi tamu aktif">
      {err && <p>⚠ {err}</p>}
      <table>
        <thead>
          <tr>
            <th>MAC</th>
            <th>IP</th>
            <th>Mulai</th>
            <th>Hangus</th>
            <th>Marketing</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {(data?.guests ?? []).map((g) => (
            <tr key={g.MAC}>
              <td>
                <code>{g.MAC}</code>
              </td>
              <td>{g.IP || "—"}</td>
              <td>{fmtTime(g.StartedAt)}</td>
              <td>{fmtTime(g.ExpiresAt)}</td>
              <td>{g.Marketing ? "✓" : "—"}</td>
              <td>
                <button className="danger" onClick={() => revoke(g.MAC)}>
                Cabut
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {(data?.guests ?? []).length === 0 && <p className="muted">Tidak ada sesi aktif.</p>}
    </Card>
  );
}

// --- vouchers tab ---

function VouchersTab() {
  const { data, err, reload } = usePoll<{ vouchers: Voucher[] }>(() => api.get(endpoints.vouchers), 8000);
  const [count, setCount] = useState(10);
  const [minutes, setMinutes] = useState(90);
  const [maxUses, setMaxUses] = useState(1);
  const [fresh, setFresh] = useState<string[]>([]);
  const create = async () => {
    try {
      const out = await api.post<{ codes: string[] }>(endpoints.vouchers, {
        count,
        duration_s: minutes * 60,
        max_uses: maxUses,
      });
      setFresh(out.codes);
      await reload();
    } catch (e) {
      alert(e instanceof Error ? e.message : e);
    }
  };
  return (
    <>
      <Card title="Generate voucher">
        <div className="row">
          <label>
            jumlah <input type="number" min={1} max={100} value={count} onChange={(e) => setCount(Number(e.target.value))} />
          </label>
          <label>
            durasi (menit) <input type="number" min={5} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} />
          </label>
          <label>
            maks. pakai <input type="number" min={1} value={maxUses} onChange={(e) => setMaxUses(Number(e.target.value))} />
          </label>
          <button onClick={create}>Generate</button>
        </div>
        {fresh.length > 0 && (
          <p className="codes">
            {fresh.map((c) => (
              <code key={c}>{c}</code>
            ))}
          </p>
        )}
      </Card>
      <Card title="Voucher">
        {err && <p>⚠ {err}</p>}
        <table>
          <thead>
            <tr>
              <th>Kode</th>
              <th>Durasi</th>
              <th>Pakai</th>
              <th>Dibuat</th>
              <th>Kedaluwarsa</th>
            </tr>
          </thead>
          <tbody>
            {(data?.vouchers ?? []).map((v) => (
              <tr key={v.Code}>
                <td>
                  <code>{v.Code}</code>
                </td>
                <td>{fmtDur(v.DurationSec)}</td>
                <td>
                  {v.Used}/{v.MaxUses}
                </td>
                <td>{fmtTime(v.CreatedAt)}</td>
                <td>{fmtTime(v.ExpiresAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(data?.vouchers ?? []).length === 0 && <p className="muted">Belum ada voucher.</p>}
      </Card>
    </>
  );
}

// --- zones tab ---

function ZonesTab() {
  const { data, err, reload } = usePoll<{ zones: Zone[] }>(() => api.get(endpoints.zones), 10000);
  const save = async (z: Zone, internet: boolean) => {
    try {
      const out = await api.put<{ change_id?: string }>(endpoints.zonePolicy(z.ID), {
        internet,
        vpn_required: z.VPNPolicy === "required",
        lan_allow: [],
      });
      await reload();
      if (out.change_id) {
        alert(
          `Zona berisiko — trial berjalan. Konfirmasi via banner di atas sebelum deadline (change ${out.change_id}).`,
        );
      }
    } catch (e) {
      alert(e instanceof Error ? e.message : e);
    }
  };
  return (
    <Card title="Zona & policy">
      {err && <p>⚠ {err}</p>}
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Nama</th>
            <th>Subnet</th>
            <th>Internet</th>
            <th>VPN</th>
            <th>Isolasi</th>
          </tr>
        </thead>
        <tbody>
          {(data?.zones ?? []).map((z) => (
            <tr key={z.ID}>
              <td>{z.ID}</td>
              <td>{z.Name}</td>
              <td>
                <code>{z.Subnet || "—"}</code>
              </td>
              <td>
                <input
                  type="checkbox"
                  checked={z.Internet}
                  onChange={(e) => save(z, e.target.checked)}
                />
              </td>
              <td>{z.VPNPolicy || "—"}</td>
              <td>{z.Isolate ? "✓" : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">
        Mengubah zona Admin otomatis masuk commit-confirm (IF-02): ruleset baru
        dicoba 60 detik dan di-rollback bila tidak dikonfirmasi.
      </p>
    </Card>
  );
}

// --- audit tab ---

function AuditTab() {
  const { data, err } = usePoll<{ audit: AuditEntry[] }>(() => api.get(endpoints.audit(200)), 8000);
  return (
    <Card title="Audit log (hash chain)">
      {err && <p>⚠ {err}</p>}
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Waktu</th>
            <th>Aktor</th>
            <th>Aksi</th>
            <th>Target</th>
            <th>Diff</th>
          </tr>
        </thead>
        <tbody>
          {(data?.audit ?? []).map((a) => (
            <tr key={a.ID}>
              <td>{a.ID}</td>
              <td>{fmtTime(a.Ts)}</td>
              <td>{a.Actor}</td>
              <td>
                <code>{a.Action}</code>
              </td>
              <td>{a.Target}</td>
              <td className="diff">{a.Diff}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

// --- app shell ---

export default function App() {
  const [authed, setAuthed] = useState(hasToken());
  const [tab, setTab] = useState<Tab>("wizard");
  const [authErr, setAuthErr] = useState(false);
  useEffect(() => {
    // A 401 anywhere means the token was rotated/expired — force re-login.
    const orig = window.fetch;
    window.fetch = async (...args) => {
      const res = await orig(...args);
      if (res.status === 401) setAuthErr(true);
      return res;
    };
    return () => {
      window.fetch = orig;
    };
  }, []);
  if (!authed || authErr) {
    return <Login onLogin={() => { setAuthErr(false); setAuthed(hasToken()); }} />;
  }
  const logout = () => {
    setToken("");
    setAuthed(false);
  };
  return (
    <div className="app">
      <header>
        <h1>kotacloud admin</h1>
        <nav>
          {TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        <button className="ghost" onClick={logout}>
          Keluar
        </button>
      </header>
      <PendingBanner />
      <main>
        {tab === "wizard" && <WizardTab />}
        {tab === "devices" && <DevicesTab />}
        {tab === "guests" && <GuestsTab />}
        {tab === "vouchers" && <VouchersTab />}
        {tab === "zones" && <ZonesTab />}
        {tab === "audit" && <AuditTab />}
      </main>
      <footer className="muted">
        REST §7.2 · {getToken() ? "token tersimpan di browser ini" : "tanpa token"}
      </footer>
    </div>
  );
}
