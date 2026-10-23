import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { get, post } from "./api.js";
import { useData } from "./ui.jsx";
import Overview from "./pages/Overview.jsx";
import Operations from "./pages/Operations.jsx";
import Console from "./pages/Console.jsx";
import Graph from "./pages/Graph.jsx";
import Trust from "./pages/Trust.jsx";
import AttackLab from "./pages/AttackLab.jsx";
import Approvals from "./pages/Approvals.jsx";
import Audit from "./pages/Audit.jsx";
import Results from "./pages/Results.jsx";
import BankData from "./pages/BankData.jsx";
import Settings from "./pages/Settings.jsx";

const ICON = {
  overview: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
  operations: "M4 17l6-5-6-5M12 19h8",
  console: "M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z",
  graph: "M5 6h4M15 6h4M7 6v12M17 6v12M7 12h10",
  trust: "M3 17l6-6 4 4 8-8",
  attack: "M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z",
  approvals: "M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11",
  audit: "M12 8v4l3 3M3 12a9 9 0 1018 0 9 9 0 00-18 0",
  results: "M4 20V10M10 20V4M16 20v-7M22 20H2",
  data: "M3 5c0-1.7 4-3 9-3s9 1.3 9 3-4 3-9 3-9-1.3-9-3zM3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3",
  settings: "M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-2.9 1.2V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-2.9-1.2l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00-1.2-2.9H3a2 2 0 110-4h.1a1.7 1.7 0 001.2-2.9l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 002.9-1.2V3a2 2 0 114 0v.1a1.7 1.7 0 002.9 1.2l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 001.2 2.9H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z",
};
const NAV = [
  ["Bank operations", [["overview", "Overview"], ["operations", "Operations"], ["data", "Bank data"], ["approvals", "Pending reviews"]]],
  ["Zero-Trust layer", [["console", "Security console"], ["graph", "Delegation graph"], ["trust", "Trust monitor"], ["audit", "Audit trail"]]],
  ["Evaluation", [["attack", "Attack lab"], ["results", "Results"], ["settings", "Settings"]]],
];

function Icon({ d }) {
  return <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>;
}

function useRoute() {
  const read = () => (location.hash.replace("#/", "") || "overview").split("?")[0];
  const [r, setR] = useState(read());
  useEffect(() => { const f = () => setR(read()); addEventListener("hashchange", f); return () => removeEventListener("hashchange", f); }, []);
  return r;
}

function App() {
  const route = useRoute();
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [appr] = useData("/api/approvals", [], 4000);
  const refreshStatus = () => get("/api/status").then(setStatus).catch(() => {});
  useEffect(() => { refreshStatus(); const t = setInterval(refreshStatus, 6000); return () => clearInterval(t); }, []);
  const pending = (appr || []).filter((a) => a.status === "PENDING").length;

  const setMode = (m) => post("/api/settings", { mode: m }).then(setStatus);
  const reset = async () => {
    if (!window.confirm("Reset the bank data, trust scores, approvals and audit ledger?")) return;
    setBusy(true); await post("/api/reset"); await refreshStatus(); setBusy(false); location.reload();
  };
  const props = { status, refreshStatus };
  const page = {
    overview: <Overview {...props} />, operations: <Operations {...props} />, console: <Console {...props} />,
    graph: <Graph />, trust: <Trust />, attack: <AttackLab {...props} />, approvals: <Approvals />,
    audit: <Audit {...props} />, results: <Results />, data: <BankData />, settings: <Settings {...props} />,
  }[route] || <Overview {...props} />;

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <div className="brand-mark"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2"><path d={ICON.console} /></svg></div>
          <div><b>FinSecure</b><span>Zero-Trust banking agents</span></div>
        </div>
        {NAV.map(([group, items]) => (
          <div key={group}>
            <div className="nav-group">{group}</div>
            <nav className="nav">{items.map(([k, label]) => (
              <a key={k} href={`#/${k}`} className={route === k ? "on" : ""}><Icon d={ICON[k]} />{label}
                {k === "approvals" && pending > 0 && <span className="count">{pending}</span>}</a>
            ))}</nav>
          </div>
        ))}
      </aside>
      <div className="main">
        <header className="top">
          <div className="mode" role="group" aria-label="Security mode">
            <button className={`secured ${status?.mode === "secured" ? "on" : ""}`} onClick={() => setMode("secured")}>Secured</button>
            <button className={`baseline ${status?.mode === "baseline" ? "on" : ""}`} onClick={() => setMode("baseline")}>Baseline</button>
          </div>
          <span className="pill"><span className={`dot ${status?.provider === "mock" ? "warn" : "ok"}`} />LLM: {status?.provider}</span>
          <span className="pill"><span className={`dot ${status?.opa ? "ok" : "warn"}`} />OPA: {status?.opa ? "server" : "built-in"}</span>
          <div className="grow" />
          <button className="btn small" onClick={reset} disabled={busy}>{busy ? "Resetting..." : "Reset environment"}</button>
        </header>
        {status?.mode === "baseline" && <div className="banner-base">Baseline mode: the gateway only logs. This is the Phase-1 system, and attacks will succeed.</div>}
        {page}
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
