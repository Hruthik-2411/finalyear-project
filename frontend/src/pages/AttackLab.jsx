import { useState } from "react";
import { post } from "../api.js";
import { LineChart } from "../chart.jsx";
import { Trace, Verdict, useData } from "../ui.jsx";
import { store } from "../store.js";

const VCOLOR = { APPROVE: "var(--approve)", RESTRICT: "var(--restrict)", BLOCK: "var(--block)", ISOLATE: "var(--isolate)", ESCALATE: "var(--escalate)" };

function Detail({ r }) {
  if (r.scenario === "reputation_laundering") {
    return (
      <>
        <LineChart height={220} step={false} xLabel="minutes" thresholds={[{ y: 0.7, label: "auto-approve 0.7" }, { y: 0.4, label: "Tier-2 blocked" }]}
          series={[{ name: "FinSecure", color: "#2a78d6", points: r.points.map((p) => ({ x: p.t_min, y: p.ours })) },
                   { name: "Linear avg", color: "#eb6834", points: r.points.map((p) => ({ x: p.t_min, y: p.linear })) }]} />
        <p className="small">Payoff transfer: <Verdict v={r.final_verdict} /> {r.final_reason}</p>
      </>
    );
  }
  if (r.scenario === "behavioural_burst") {
    return (
      <div className="row" style={{ gap: 3 }}>
        {r.verdicts.map((v, i) => <span key={i} title={`request ${i + 1}: ${v}`}
                                         style={{ width: 12, height: 22, borderRadius: 3, display: "inline-block", background: VCOLOR[v] || "#718096" }} />)}
        <span className="small muted" style={{ marginLeft: 8 }}>one bar per request: green approved, slate restricted, violet isolated</span>
      </div>
    );
  }
  if (r.scenario === "audit_tampering") {
    const v = r.verification;
    return (
      <div className="small">
        <p>Edited event #{r.edited_seq}, deleted event #{r.deleted_seq}. Ledger: {v.batches} sealed batches, {v.events_checked} events checked.</p>
        <ul>{v.problems.length ? v.problems.map((p, i) => <li key={i}>event {p.seq}: {p.problem}</li>) : <li>No integrity check possible: nothing was sealed.</li>}</ul>
      </div>
    );
  }
  if (r.trace) return <details><summary>Gateway checkpoints ({r.trace.length})</summary><Trace trace={r.trace} mode={r.mode} /></details>;
  return <p className="small">{r.reason}</p>;
}

function Result({ r }) {
  if (!r) return <div className="res"><span className="muted small">Not run yet.</span></div>;
  return (
    <div className={`res ${r.attack_succeeded ? "hit" : "safe"}`}>
      <h3>{r.mode === "baseline" ? "Baseline" : "Secured"}: {r.attack_succeeded ? "attack succeeded" : "attack stopped"}</h3>
      <p className="small" style={{ marginBottom: 8 }}>{r.summary}</p>
      <Detail r={r} />
    </div>
  );
}

export default function AttackLab({ status, refreshStatus }) {
  const [list] = useData("/api/scenarios");
  const [res, setRes] = useState(store.scenarioResults);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function runBoth(id) {
    setBusy(id); setErr(null);
    const original = status?.mode || "secured";
    try {
      const out = {};
      for (const m of ["baseline", "secured"]) {
        await post("/api/settings", { mode: m });
        out[m] = await post(`/api/scenarios/${id}`);
      }
      store.scenarioResults = { ...store.scenarioResults, [id]: out };
      setRes(store.scenarioResults);
    } catch (e) { setErr(e.message); }
    await post("/api/settings", { mode: original }).catch(() => {});
    refreshStatus && refreshStatus();
    setBusy(null);
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Attack lab</h1>
          <p>Each scenario resets the bank, plants the attack and runs it twice: once on the Phase-1 baseline and once with the
            Zero-Trust layer on. Watch the Security console in another tab to see each envelope as it is decided.</p>
        </div>
      </div>
      {err && <div className="err" style={{ marginBottom: 12 }}>{err}</div>}
      {(list || []).map((s) => (
        <div className="panel" key={s.id}>
          <div className="panel-head">
            <div><h2>{s.title}</h2><p className="muted small" style={{ marginTop: 3 }}>{s.description}</p></div>
            <button className="btn primary" disabled={!!busy} onClick={() => runBoth(s.id)}>
              {busy === s.id ? "Running..." : res[s.id] ? "Run again" : "Run baseline vs secured"}
            </button>
          </div>
          {res[s.id] && <div className="scn"><Result r={res[s.id].baseline} /><Result r={res[s.id].secured} /></div>}
        </div>
      ))}
    </div>
  );
}
