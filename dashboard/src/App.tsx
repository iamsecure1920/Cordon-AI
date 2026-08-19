import { useEffect, useMemo, useState } from "react";
import {
  LayoutDashboard, Bug, Globe, ShieldCheck, Activity, Wrench,
  FilterX, FileText, Brain,
} from "lucide-react";
import { useLiveState } from "./api";
import { LiveDot, EmptyState } from "./components/ui";
import { Overview } from "./views/Overview";
import { Findings } from "./views/Findings";
import { Assets } from "./views/Assets";
import { Coverage } from "./views/Coverage";
import { Activity as ActivityView } from "./views/Activity";
import { Tools } from "./views/Tools";
import { FalsePositives } from "./views/FalsePositives";
import { Reports } from "./views/Reports";

type View = "overview" | "findings" | "assets" | "coverage" | "activity" | "tools" | "fp" | "reports";

const NAV: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "findings", label: "Findings", icon: Bug },
  { id: "assets", label: "Assets", icon: Globe },
  { id: "coverage", label: "Coverage", icon: ShieldCheck },
  { id: "activity", label: "Activity", icon: Activity },
  { id: "tools", label: "Tools", icon: Wrench },
  { id: "fp", label: "False positives", icon: FilterX },
  { id: "reports", label: "Reports", icon: FileText },
];

function viewFromHash(): View {
  const h = window.location.hash.replace("#", "") as View;
  return NAV.some((n) => n.id === h) ? h : "overview";
}

function wsFromUrl(): string | undefined {
  return new URLSearchParams(window.location.search).get("ws") || undefined;
}

export default function App() {
  const [view, setView] = useState<View>(viewFromHash);
  const [ws, setWs] = useState<string | undefined>(wsFromUrl);
  const { state, error, connected } = useLiveState(2000, ws);

  // keep the ?ws= deep-link in the URL when the workspace changes
  const selectWs = (v?: string) => {
    setWs(v);
    const p = new URLSearchParams(window.location.search);
    if (v) p.set("ws", v); else p.delete("ws");
    const q = p.toString();
    window.history.replaceState(
      null, "", `${q ? `?${q}` : ""}${window.location.hash}`);
  };

  // keep back/forward + deep links (#findings, #assets, …) working
  const navigate = (v: View) => {
    setView(v);
    window.location.hash = v;
  };
  useEffect(() => {
    const onHash = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const workspaceNames = useMemo(
    () => (state?.workspaces ?? []).map((w) => w.name),
    [state],
  );

  const counts: Partial<Record<View, number>> = useMemo(() => {
    if (!state) return {};
    return {
      findings: state.findings?.total ?? 0,
      assets: Object.values(state.assets ?? {}).reduce((a, b) => a + b, 0),
      fp: state.false_positives?.length ?? 0,
    };
  }, [state]);

  if (!state || state.workspace == null) {
    return (
      <div className="app">
        <div style={{ flex: 1, display: "grid", placeItems: "center" }}>
          <div style={{ maxWidth: 520, textAlign: "center" }}>
            <Brain size={44} color="var(--accent)" style={{ marginBottom: 16 }} />
            <EmptyState>
              <b>{state?.error ?? "Connecting to engagement state…"}</b>
              <br /><br />
              Run a phase or <span className="mono">./scripts/hunt.sh &lt;target&gt;</span> first, then start
              <span className="mono"> easyhunt dashboard --serve</span> and open this page.
              <br />
              {error ? <div style={{ color: "var(--fail)", marginTop: 10 }}>{error}</div> : null}
            </EmptyState>
          </div>
        </div>
      </div>
    );
  }

  const running = state.running_phase;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">🧠</div>
          <div>
            <h1>EasyHunt AI</h1>
            <small>Engagement ops</small>
          </div>
        </div>
        {NAV.map(({ id, label, icon: Icon }) => (
          <button key={id} className={`nav-item ${view === id ? "active" : ""}`} onClick={() => navigate(id)}>
            <Icon size={16} />
            {label}
            {counts[id] ? <span className="count">{counts[id]}</span> : null}
          </button>
        ))}
        <div className="sidebar-foot">
          <b>Brain online</b> · sensing via audit log
          <br />
          {state.findings?.total ?? 0} findings · {(state.completed_count ?? 0)} phases done
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <span className="title">{NAV.find((n) => n.id === view)?.label ?? "Overview"}</span>
          <span className="ws">{state.workspace_name}</span>
          <div className="spacer" />
          <select
            className="select-ws"
            value={ws ?? ""}
            onChange={(e) => selectWs(e.target.value || undefined)}
            title="Switch engagement workspace"
          >
            <option value="">newest workspace</option>
            {workspaceNames.map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <LiveDot connected={connected} running={running} />
          <span style={{ color: "var(--faint)", fontSize: 11, fontFamily: "var(--mono)" }}>
            {state.generated_at?.slice(5, 19).replace("T", " ")}
          </span>
        </header>

        <div className="content">
          {view === "overview" && <Overview state={state} />}
          {view === "findings" && <Findings state={state} />}
          {view === "assets" && <Assets state={state} />}
          {view === "coverage" && <Coverage state={state} />}
          {view === "activity" && <ActivityView state={state} />}
          {view === "tools" && <Tools state={state} />}
          {view === "fp" && <FalsePositives state={state} />}
          {view === "reports" && <Reports state={state} />}
        </div>
      </main>
    </div>
  );
}
