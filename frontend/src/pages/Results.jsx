import { useData } from "../ui.jsx";

const COLS = [
  ["benign_utility", "Benign tasks completed"], ["false_positive_rate", "False positives"],
  ["utility_under_attack", "Completed under attack"], ["utility_under_attack_with_human", "...incl. human approval"],
  ["attack_success_rate", "Attack success"], ["latency_p50_ms", "Latency p50 (ms)"], ["llm_calls_mean", "LLM calls per run"],
];

export default function Results() {
  const [d] = useData("/api/results");
  if (!d) return <div className="page"><div className="empty">Loading...</div></div>;
  if (!d.available) return (
    <div className="page"><h1>Results</h1>
      <div className="panel empty" style={{ marginTop: 16 }}>No evaluation results yet. Run <code>python run.py eval --quick</code> in a terminal, then reload this page.</div>
    </div>
  );
  const fmt = (k, v) => v === null || v === undefined ? "-" : k.includes("ms") || k.includes("calls") ? v : `${v}%`;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Evaluation results</h1>
          <p>From <b>{d.file}</b>, produced with the <b>{d.provider}</b> LLM provider.
            {d.provider === "mock" && " Mock results come from the offline worst-case model that always obeys injected text. Re-run with Groq for the numbers you report."}</p>
        </div>
      </div>
      <div className="panel">
        <h2>Summary by configuration</h2>
        <div className="scroll" style={{ marginTop: 10 }}>
          <table className="t">
            <thead><tr><th>Configuration</th>{COLS.map(([k, l]) => <th key={k}>{l}</th>)}</tr></thead>
            <tbody>{Object.entries(d.configs).map(([c, v]) => (
              <tr key={c}><td><b>{c.replace("no_", "without ").replace("only_", "only ")}</b><div className="small muted">{v.benign_runs} benign, {v.attack_runs} attack runs</div></td>
                {COLS.map(([k]) => <td key={k}>{fmt(k, v[k])}</td>)}</tr>))}</tbody>
          </table>
        </div>
      </div>
      {Object.keys(d.scenarios || {}).length > 0 && (
        <div className="panel">
          <h2>Attack-class scenarios</h2>
          <table className="t" style={{ marginTop: 10 }}>
            <thead><tr><th>Scenario</th><th>Baseline</th><th>Secured</th></tr></thead>
            <tbody>{Object.entries(d.scenarios).map(([s, v]) => (
              <tr key={s}><td><b>{s.replace(/_/g, " ")}</b></td>
                <td className="small" style={{ color: v.baseline?.attack_success ? "var(--block)" : "inherit" }}>{v.baseline?.summary}</td>
                <td className="small" style={{ color: v.secured?.attack_success ? "var(--block)" : "var(--approve)" }}>{v.secured?.summary}</td></tr>))}</tbody>
          </table>
        </div>
      )}
      <div className="grid g2" style={{ marginTop: 16 }}>
        {(d.charts || []).map((c) => (
          <div className="panel" key={c}><img src={`/results/${c}`} alt={c} style={{ width: "100%" }} /></div>
        ))}
      </div>
    </div>
  );
}
