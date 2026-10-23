import { useState } from "react";
import { post } from "../api.js";

const MODS = [
  ["identity", "Identity verification", "X.509 certificates and signed envelopes"],
  ["intent", "Intent scope and delegation chain", "Every tool call must trace back to, and fit, the signed request"],
  ["shield", "Prompt Shield", "Scans untrusted data for injected instructions"],
  ["policy", "OPA policy engine", "Role and attribute rules (limits, frozen accounts, PII)"],
  ["burst", "Burst limiter", "Rate and money-velocity limits per agent"],
  ["trust", "Behavioural trust", "Non-linear trust score with time-based recovery"],
];

export default function Settings({ status, refreshStatus }) {
  const [err, setErr] = useState(null);
  if (!status) return null;
  const set = (body) => post("/api/settings", body).then(() => { setErr(null); refreshStatus(); }).catch((e) => setErr(e.message));
  return (
    <div className="page">
      <div className="page-head"><div><h1>Settings</h1><p>Changes apply immediately and last until the server restarts. Defaults live in config.yaml.</p></div></div>
      {err && <div className="err" style={{ marginBottom: 12 }}>{err}</div>}
      <div className="grid g2">
        <div className="panel">
          <h2>Language model</h2>
          <div className="row" style={{ marginTop: 12 }}>
            {["groq", "ollama", "mock"].map((p) => (
              <button key={p} className={`btn ${status.provider === p ? "primary" : ""}`} onClick={() => set({ provider: p })}>{p}</button>
            ))}
          </div>
          <p className="small muted" style={{ marginTop: 10 }}>
            Groq needs GROQ_API_KEY in .env (key {status.groq_key ? "found" : "not found"}). Ollama needs the Ollama app running.
            Mock works offline and always obeys injected text, so it is a worst-case model.
          </p>
          <h2 style={{ marginTop: 18 }}>Components</h2>
          <table className="t" style={{ marginTop: 8 }}><tbody>
            <tr><td>OPA server</td><td>{status.opa ? "connected (real OPA decides)" : "not running (built-in evaluator with the same rules)"}</td></tr>
            <tr><td>LangGraph</td><td>{status.langgraph ? "installed" : "not installed (compatible runner)"}</td></tr>
            <tr><td>LLM calls this session</td><td>{status.llm_stats.calls} calls, {status.llm_stats.tokens} tokens</td></tr>
          </tbody></table>
        </div>
        <div className="panel">
          <h2>Security modules</h2>
          <p className="small muted" style={{ marginTop: 4 }}>Switch one off to show what it contributes. Only used in Secured mode.</p>
          <table className="t" style={{ marginTop: 8 }}><tbody>
            {MODS.map(([k, l, d]) => (
              <tr key={k}><td><label style={{ display: "flex", gap: 10, alignItems: "flex-start", cursor: "pointer" }}>
                <input type="checkbox" checked={!!status.modules[k]} onChange={(e) => set({ modules: { [k]: e.target.checked } })} />
                <span><b>{l}</b><div className="small muted">{d}</div></span></label></td></tr>
            ))}</tbody></table>
        </div>
      </div>
    </div>
  );
}
