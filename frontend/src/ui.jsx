import { useEffect, useRef, useState, useCallback } from "react";
import { get } from "./api.js";

export const CHECK_ORDER = ["identity", "chain", "intent", "policy", "shield", "burst", "trust"];
export const CHECK_LABEL = {
  identity: "Identity", chain: "Chain", intent: "Intent scope", policy: "OPA policy",
  shield: "Prompt Shield", burst: "Burst", trust: "Trust",
};

export function useData(path, deps = [], interval = 0) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const load = useCallback(() => {
    if (!path) return;
    get(path).then((d) => { setData(d); setError(null); }).catch((e) => setError(e.message));
  }, [path]);
  useEffect(() => {
    load();
    if (interval) {
      const t = setInterval(load, interval);
      return () => clearInterval(t);
    }
  }, [load, interval, ...deps]);
  return [data, load, error];
}

/** Live gateway events over WebSocket, with polling fallback. */
export function useEvents(onEvent) {
  const cb = useRef(onEvent);
  cb.current = onEvent;
  useEffect(() => {
    let last = 0, ws = null, timer = null, closed = false;
    const handle = (list) => list.forEach((e) => { last = Math.max(last, e.id); cb.current(e); });
    const poll = () => get(`/api/events?since=${last}`).then(handle).catch(() => {});
    try {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onmessage = (m) => handle(JSON.parse(m.data));
      ws.onerror = () => { if (!timer && !closed) timer = setInterval(poll, 1000); };
      ws.onclose = () => { if (!timer && !closed) timer = setInterval(poll, 1000); };
    } catch (e) {
      timer = setInterval(poll, 1000);
    }
    return () => { closed = true; if (ws) ws.close(); if (timer) clearInterval(timer); };
  }, []);
}

export function Verdict({ v }) {
  return <span className={`verdict v-${v}`}>{v}</span>;
}

export function Stat({ label, value, note }) {
  return (
    <div className="panel stat">
      <div className="l">{label}</div>
      <div className="v">{value}</div>
      {note && <div className="muted small">{note}</div>}
    </div>
  );
}

export function rupees(x) {
  if (x === null || x === undefined) return "-";
  return "Rs " + Number(x).toLocaleString("en-IN", { maximumFractionDigits: 0 });
}

function short(args) {
  if (!args || !Object.keys(args).length) return "";
  return Object.entries(args).map(([k, v]) => `${k}=${typeof v === "number" ? v.toLocaleString("en-IN") : v}`).join(", ");
}

/** One envelope as a checkpoint strip: who -> where, each check lit pass/fail, the verdict. */
export function CheckStrip({ t, mode }) {
  const byName = Object.fromEntries((t.checks || []).map((c) => [c.name, c]));
  const target = t.tool ? `${t.tool}(${short(t.args)})` : t.receiver;
  const showChecks = t.kind !== "intent" && t.verdict !== "SANITIZED";
  return (
    <div className="strip">
      <div className="who">{t.sender}<span title={target}>{t.kind === "tool_call" ? "calls " : "to "}{target.length > 40 ? target.slice(0, 40) + "..." : target}</span></div>
      <div className="checks">
        {showChecks && (t.mode === "baseline" || mode === "baseline") && !(t.checks || []).length &&
          <span className="ck skip">baseline: no checks, logged only</span>}
        {showChecks && CHECK_ORDER.filter((n) => byName[n]).map((n) => (
          <span key={n} className={`ck ${byName[n].passed ? "pass" : n === "trust" ? "warn" : "fail"}`} title={byName[n].detail}>
            {CHECK_LABEL[n]}
          </span>
        ))}
      </div>
      <div><Verdict v={t.verdict === "APPROVE" && t.mode === "baseline" ? "APPROVE" : t.verdict} /></div>
      {(t.verdict !== "APPROVE" || t.kind === "intent") && <div className="reason">{t.reason}</div>}
    </div>
  );
}

export function Trace({ trace, mode }) {
  if (!trace || !trace.length) return <div className="empty">No envelopes yet.</div>;
  return <div>{trace.map((t, i) => <CheckStrip key={t.msg_id + i} t={t} mode={mode} />)}</div>;
}
