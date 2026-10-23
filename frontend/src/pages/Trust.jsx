import { post } from "../api.js";
import { LineChart, SERIES } from "../chart.jsx";
import { useData } from "../ui.jsx";

const AGENTS = ["orchestrator", "planner", "researcher", "executor", "auditor"];

export default function Trust() {
  const [d, reload] = useData("/api/trust", [], 2000);
  if (!d) return <div className="page"><div className="empty">Loading...</div></div>;
  const t0 = d.history.length ? d.history[0].ts : 0;
  const span = d.history.length ? d.history[d.history.length - 1].ts - t0 : 0;
  const unit = span < 120 ? 1 : 60;               // seconds for short sessions, minutes otherwise
  const series = AGENTS.map((a, i) => ({
    name: a, color: SERIES[i],
    points: d.history.filter((h) => h.agent === a).map((h) => ({ x: (h.ts - t0) / unit, y: h.score })),
  }));
  const th = d.thresholds;
  const events = d.history.filter((h) => !h.event.startsWith("good") && h.event !== "init").slice(-25).reverse();
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Trust monitor</h1>
          <p>Trust falls sharply on a violation and recovers only as time passes (the recovery ceiling), not through
            the number of actions. Irreversible actions need trust of at least {th.normal}. Below {th.restricted} they are blocked,
            and below {th.blocked} the agent is isolated.</p>
        </div>
      </div>
      <div className="panel">
        <LineChart series={series} xLabel={unit === 1 ? "seconds" : "minutes"} thresholds={[
          { y: th.normal, label: `auto-approve ${th.normal}` }, { y: th.restricted, label: `Tier-2 blocked < ${th.restricted}` },
          { y: th.blocked, label: `isolate < ${th.blocked}` }]} />
      </div>
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <h2>Current scores</h2>
          <table className="t" style={{ marginTop: 10 }}>
            <thead><tr><th>Agent</th><th>Trust</th><th>Ceiling</th><th>Recent blocks</th><th></th></tr></thead>
            <tbody>{AGENTS.map((a) => { const c = d.current[a] || {}; return (
              <tr key={a}><td>{a}</td><td><b>{c.score?.toFixed(3)}</b></td><td>{c.ceiling?.toFixed(3)}</td><td>{c.recent_blocks}</td>
                <td>{c.score < th.blocked && <button className="btn small" onClick={() => post(`/api/agents/${a}/reinstate`).then(reload)}>Reinstate</button>}</td></tr>);
            })}</tbody>
          </table>
        </div>
        <div className="panel">
          <h2>Violations and isolations</h2>
          {!events.length && <p className="muted small" style={{ marginTop: 8 }}>None yet.</p>}
          <table className="t" style={{ marginTop: 10 }}><tbody>
            {events.map((h, i) => <tr key={i}><td>{h.agent}</td><td>{h.score.toFixed(2)}</td><td className="small">{h.event}</td></tr>)}
          </tbody></table>
        </div>
      </div>
    </div>
  );
}
