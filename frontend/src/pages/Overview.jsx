import { Stat, Verdict, rupees, useData } from "../ui.jsx";

export default function Overview({ status }) {
  const [o] = useData("/api/overview", [], 3000);
  const [runs] = useData("/api/runs?limit=8", [], 3000);
  if (!o) return <div className="page"><div className="empty">Loading...</div></div>;
  const dec = o.decisions || {};
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>FinSecure runs bank operations with five AI agents. The Zero-Trust gateway checks every message and tool call
            they make, on every step rather than once at login.</p>
        </div>
      </div>
      <div className="grid g4">
        <Stat label="Accounts under management" value={o.accounts} note={rupees(o.total_balance) + " total"} />
        <Stat label="Open fraud cases" value={o.open_cases} note={`${o.frozen} accounts frozen`} />
        <Stat label="Waiting for human review" value={o.pending_approvals} note={<a href="#/approvals">Open reviews</a>} />
        <Stat label="Attacker account ACC-9999" value={rupees(o.attacker_balance)} note="Starts at Rs 1,000" />
      </div>
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <h2>Gateway decisions so far</h2>
          <div className="row" style={{ marginTop: 12, gap: 18 }}>
            {["APPROVE", "ESCALATE", "RESTRICT", "BLOCK", "ISOLATE"].map((v) => (
              <div key={v}><Verdict v={v} /><div style={{ fontSize: 22, fontWeight: 700, marginTop: 6 }}>{dec[v] || 0}</div></div>
            ))}
          </div>
          <h3 style={{ marginTop: 18 }}>Agent trust</h3>
          <table className="t" style={{ marginTop: 6 }}><tbody>
            {Object.entries(o.trust).map(([a, t]) => (
              <tr key={a}><td>{a}</td><td style={{ width: "60%" }}>
                <div style={{ background: "var(--line-2)", borderRadius: 4, height: 8 }}>
                  <div style={{ width: `${t.score * 100}%`, height: 8, borderRadius: 4,
                    background: t.score >= 0.7 ? "var(--vault)" : t.score >= 0.4 ? "var(--escalate)" : "var(--block)" }} />
                </div></td><td><b>{t.score.toFixed(2)}</b></td></tr>
            ))}</tbody></table>
        </div>
        <div className="panel">
          <h2>Recent operations</h2>
          {!(runs || []).length ? <div className="empty">No operations yet. <a href="#/operations">Run one</a>.</div> : (
            <table className="t" style={{ marginTop: 10 }}><tbody>
              {runs.map((r) => (
                <tr key={r.id}><td className="small">{r.started.slice(11, 19)}</td><td>{r.request}<div className="small muted">{r.mode} | {r.duration_ms} ms</div></td></tr>
              ))}</tbody></table>
          )}
        </div>
      </div>
      <div className="panel" style={{ marginTop: 16 }}>
        <h2>How to demo</h2>
        <ol className="small" style={{ lineHeight: 1.8, margin: "8px 0 0", paddingLeft: 18 }}>
          <li>Operations: run "Make transfer" and walk through the checkpoint strip and the signed intent.</li>
          <li>Attack lab: run each scenario. The baseline result is on the left and the secured result on the right.</li>
          <li>Trust monitor and Delegation graph: show why each decision was made.</li>
          <li>Audit trail: tamper with a row, then verify the ledger.</li>
          <li>Results: show the evaluation numbers and the ablation chart.</li>
        </ol>
      </div>
    </div>
  );
}
