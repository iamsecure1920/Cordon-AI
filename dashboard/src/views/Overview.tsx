import type { DashboardState } from "../types";
import { StatCard, Badge, EmptyState } from "../components/ui";

export function Overview({ state }: { state: DashboardState }) {
  const f = state.findings;
  const sev = f.by_severity;
  const st = f.by_status;
  const assets = state.assets;
  const assetTotal = Object.values(assets).reduce((a, b) => a + b, 0);
  const cov = state.coverage;

  type CardCls = "crit" | "high" | "low" | "med" | "run" | "dim" | "ok";
  const cards: { k: string; v: number; cls: CardCls; sub: string }[] = [
    { k: "Findings", v: f.total, cls: f.total ? "med" : "ok",
      sub: sevText(sev) },
    { k: "Confirmed", v: st.confirmed ?? 0, cls: "ok",
      sub: `review: ${st.needs_manual_review ?? 0}` },
    { k: "Candidates", v: st.candidate ?? 0, cls: "run",
      sub: "awaiting validation" },
    { k: "False positives", v: state.false_positives.length,
      cls: state.false_positives.length ? "crit" : "dim",
      sub: "dismissed + learned" },
    { k: "Crit/High", v: (sev.critical ?? 0) + (sev.high ?? 0), cls: "crit",
      sub: `med ${sev.medium ?? 0} · low ${sev.low ?? 0}` },
    { k: "Phases done", v: state.completed_count, cls: "ok",
      sub: state.running_phase ? `running: ${state.running_phase}` : "pipeline idle" },
    { k: "Assets", v: assetTotal, cls: "dim",
      sub: `subdomains ${assets.subdomain ?? 0} · endpoints ${assets.endpoint ?? 0}` },
    { k: "Classes covered", v: cov.total, cls: "ok",
      sub: `${cov.by_status.validated ?? 0} validated this run` },
  ];

  return (
    <div>
      <div className="grid-cards">
        {cards.map((c) => (
          <StatCard key={c.k} k={c.k} v={c.v} cls={c.cls} sub={c.sub} />
        ))}
      </div>

      <div className="section-title">Phase pipeline <span className="rule" /></div>
      <PhaseStrip state={state} />

      <div className="section-title">Live sensing <span className="rule" /></div>
      <QuickActivity state={state} />
    </div>
  );
}

function sevText(s: Record<string, number | undefined>): string {
  const parts: string[] = [];
  if (s.critical) parts.push(`crit ${s.critical}`);
  if (s.high) parts.push(`high ${s.high}`);
  if (s.medium) parts.push(`med ${s.medium}`);
  if (s.low) parts.push(`low ${s.low}`);
  return parts.join(" · ") || "no findings yet";
}

export function PhaseStrip({ state }: { state: DashboardState }) {
  const phases = state.phases;
  const order = state.phase_order?.length ? state.phase_order : Object.keys(phases);
  return (
    <div className="pipeline">
      {order.map((p) => {
        const e = phases[p] ?? { state: "pending" as const, tool: null, seconds: null, findings: null, message: null, phase: p };
        return (
          <div key={p} className={`ph ${e.state}`}>
            <div className="nm">{p}</div>
            <div className="st">{e.state}</div>
            {e.tool ? <div className="tool">{e.tool}</div> : null}
            {e.seconds != null ? <div className="secs">{e.seconds.toFixed(1)}s</div> : null}
          </div>
        );
      })}
    </div>
  );
}

function QuickActivity({ state }: { state: DashboardState }) {
  const events = state.activity ?? [];
  const latest = events.slice(-10).reverse();
  if (!latest.length) {
    return <EmptyState><b>No sensed activity yet.</b><br />Run a phase or hunt.sh — every tool call is sensed here.</EmptyState>;
  }
  return (
    <div className="feed">
      {latest.map((e, i) => (
        <div className="fe" key={`${e.ts}-${i}`}>
          <span className="t">{(e.ts ?? "").replace("T", " ").slice(5, 19)}</span>
          <span className="ph2">{e.phase || "?"}</span>
          <span className="tl">{e.tool || "?"}</span>
          <span className={`o-${e.outcome ?? "ok"}`}>{e.outcome}</span>
          {e.findings ? <span className="hits">★{e.findings}</span> : null}
        </div>
      ))}
    </div>
  );
}

export function FindingBadges({ finding }: { finding: { severity: string; status: string } }) {
  return (
    <span className="row" style={{ gap: 6 }}>
      <Badge kind="sev" value={finding.severity} />
      <Badge kind="st" value={finding.status} />
    </span>
  );
}
