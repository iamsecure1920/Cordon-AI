import { useMemo, useState } from "react";
import type { DashboardState, ActivityEvent } from "../types";
import { SearchInput, Select, EmptyState } from "../components/ui";

export function Activity({ state }: { state: DashboardState }) {
  const events = state.activity ?? [];
  const [search, setSearch] = useState("");
  const [phase, setPhase] = useState("");
  const [tool, setTool] = useState("");
  const [outcome, setOutcome] = useState("");

  const phases = useMemo(() => [...new Set(events.map((e) => e.phase).filter(Boolean))].sort(), [events]);
  const tools = useMemo(() => [...new Set(events.map((e) => e.tool).filter(Boolean))].sort(), [events]);
  const outcomes = useMemo(() => [...new Set(events.map((e) => e.outcome).filter(Boolean))].sort(), [events]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events
      .filter((e) => {
        if (q && !`${e.tool} ${e.phase}`.toLowerCase().includes(q)) return false;
        if (phase && e.phase !== phase) return false;
        if (tool && e.tool !== tool) return false;
        if (outcome && e.outcome !== outcome) return false;
        return true;
      })
      .slice()
      .reverse();
  }, [events, search, phase, tool, outcome]);

  return (
    <div>
      <div className="filterbar">
        <SearchInput value={search} onChange={setSearch} placeholder="search tool or phase…" />
        <Select value={phase} onChange={setPhase} options={phases} allLabel="all phases" />
        <Select value={tool} onChange={setTool} options={tools} allLabel="all tools" />
        <Select value={outcome} onChange={setOutcome} options={outcomes} allLabel="all outcomes" />
        <span style={{ marginLeft: "auto", color: "var(--faint)", fontSize: 12 }}>
          {filtered.length} events · last {events.length} sensed
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState><b>No sensed activity.</b><br />The brain observes every tool call through the audit log while a run is active.</EmptyState>
      ) : (
        <div className="feed">
          {filtered.map((e: ActivityEvent, i: number) => (
            <div className="fe" key={`${e.ts}-${i}`}>
              <span className="t">{(e.ts ?? "").replace("T", " ").slice(5, 19)}</span>
              <span className="ph2">{e.phase || "?"}</span>
              <span className="tl">{e.tool || "?"}</span>
              <span className={`o-${e.outcome ?? "ok"}`}>{e.outcome}</span>
              {e.findings ? <span className="hits">★{e.findings}</span> : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
