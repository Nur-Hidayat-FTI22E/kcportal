import { useEffect, useRef, useState } from "react";

// Contract mirrors portaledge exactly: GET /state (JSON, identified by
// source IP), POST / (form-encoded, terms=yes, 303 back on success),
// catch-all 302 for OS captive probes. Identity NEVER comes from the
// client side — the server resolves it from the kernel neighbor table
// (DD-10).

interface StateView {
  mac: string;
  authorized: boolean;
  expires_at?: string;
  state?: string;
}

const TERMS_VERSION = __TERMS_VERSION__;

export default function App() {
  const [st, setSt] = useState<StateView | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "forbidden">("loading");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState("");
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const load = async () => {
      try {
        const r = await fetch("/state", { cache: "no-store" });
        if (r.status === 403) {
          if (alive) setPhase("forbidden");
          return; // stop polling: identity gone (Wi-Fi dropped)
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = (await r.json()) as StateView;
        if (!alive) return;
        setSt(j);
        setPhase("ready");
        // Unauthorized: keep polling (3 s) so an admin-side approval
        // flips this page to "connected" by itself — same cadence the
        // old inline script used.
        if (!j.authorized) timer = window.setTimeout(load, 3000);
      } catch {
        if (alive) setPhase("forbidden");
      }
    };
    load();
    return () => {
      alive = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, []);

  if (phase === "loading") {
    return <div className="wrap center muted">Memuat…</div>;
  }

  if (phase === "forbidden") {
    return (
      <div className="wrap">
        <div className="card">
          <h2>KotaCloud WiFi</h2>
          <p className="warn">
            Identitas perangkat tidak ditemukan. Hubungkan ulang Wi-Fi
            (matikan lalu nyalakan lagi), kemudian buka halaman ini.
          </p>
        </div>
      </div>
    );
  }

  if (st?.authorized) {
    return (
      <div className="wrap">
        <div className="card">
          <h2>KotaCloud WiFi</h2>
          <p className="ok">
            <strong>Tersambung — internet aktif.</strong>
          </p>
          <p>
            Sesi tamu: <code>{st.mac}</code>
            {st.expires_at && (
              <>
                , berlaku sampai{" "}
                <strong>
                  {new Date(st.expires_at).toLocaleTimeString("id-ID", {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </strong>
              </>
            )}
            .
          </p>
          <p className="muted">
            Halaman ini bisa ditutup. Internet berhenti otomatis saat masa
            sesi habis.
          </p>
        </div>
      </div>
    );
  }

  const submit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setFormErr("");
    // Same wire contract as the native form (form-encoded POST to /),
    // but errors render inline instead of replacing the page with raw
    // JSON: redirect:"manual" surfaces the 303 as an opaque redirect
    // (= success → reload to the authorized screen); 400/409 carry the
    // server's Indonesian message (terms missing / invalid voucher).
    const form = formRef.current;
    if (!form) return;
    fetch("/", {
      method: "POST",
      redirect: "manual",
      body: new URLSearchParams(new FormData(form) as unknown as Record<string, string>),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    })
      .then(async (r) => {
        if (r.type === "opaqueredirect" || r.status === 303) {
          window.location.reload();
          return;
        }
        const j = (await r.json().catch(() => ({}))) as { error?: string };
        setFormErr(j.error ?? `gagal (HTTP ${r.status}) — coba lagi`);
      })
      .catch(() => setFormErr("jaringan bermasalah — coba lagi"))
      .finally(() => setBusy(false));
  };

  return (
    <div className="wrap">
      <div className="card">
        <h2>KotaCloud WiFi</h2>
        <p>Selamat datang! Untuk memakai internet, mohon setujui syarat &amp; ketentuan.</p>
        <p className="muted">
          MAC: <code>{st?.mac}</code> · syarat v{TERMS_VERSION}
        </p>
        <form ref={formRef} method="POST" action="/" onSubmit={submit}>
          <label className="check">
            <input type="checkbox" name="terms" value="yes" required />
            <span>
              Saya setuju dengan <strong>syarat &amp; ketentuan</strong>{" "}
              penggunaan.
            </span>
          </label>
          <label className="check">
            <input type="checkbox" name="marketing" value="yes" />
            <span>
              (Opsional) Saya bersedia menerima info promo. Data di bawah
              hanya dipakai untuk itu.
            </span>
          </label>
          <label htmlFor="f-name">Nama</label>
          <input id="f-name" type="text" name="name" autoComplete="name" />
          <label htmlFor="f-contact">Kontak (email/WA)</label>
          <input id="f-contact" type="text" name="contact" autoComplete="email" />
          <label htmlFor="f-voucher">Kode voucher (opsional)</label>
          <input
            id="f-voucher"
            type="text"
            name="voucher"
            autoComplete="off"
            className="upper"
          />
          {formErr && <p className="warn">{formErr}</p>}
          <button type="submit" disabled={busy}>
            {busy ? "Menyambungkan…" : "Sambungkan Internet"}
          </button>
        </form>
      </div>
    </div>
  );
}
