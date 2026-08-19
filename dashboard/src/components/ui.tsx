import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Search, X } from "lucide-react";

/* ---------- Badge ---------- */
export function badgeClass(kind: "sev" | "st", value: string): string {
  const v = String(value ?? "").toLowerCase().replace(/[^a-z0-9_]/g, "_");
  return `${kind === "sev" ? "sev" : "st"}-${v}`;
}

export function Badge({ kind, value }: { kind: "sev" | "st"; value: string }) {
  return <span className={`badge ${badgeClass(kind, value)}`}>{String(value ?? "?")}</span>;
}

/* ---------- Stat card ---------- */
export function StatCard({
  k,
  v,
  cls = "dim",
  sub,
  suffix,
}: {
  k: string;
  v: number | string;
  cls?: "crit" | "high" | "med" | "low" | "ok" | "run" | "dim";
  sub?: string;
  suffix?: string;
}) {
  const key = `${k}:${v}:${suffix ?? ""}`;
  return (
    <div className="card">
      <div className="k">{k}</div>
      <div className={`v ${cls}`}>
        <span key={key} className="count-anim">{v}</span>
        {suffix ? <span style={{ fontSize: 13, opacity: 0.7 }}> {suffix}</span> : null}
      </div>
      {sub ? <div className="sub">{sub}</div> : null}
    </div>
  );
}

/* ---------- Live dot ---------- */
export function LiveDot({ connected, running }: { connected: boolean; running: string | null }) {
  const cls = !connected ? "live off" : running ? "live" : "live stale";
  return (
    <span className={cls}>
      <span className="dot" />
      {!connected ? "offline" : running ? `running: ${running}` : "idle"}
    </span>
  );
}

/* ---------- Empty ---------- */
export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/* ---------- Search input ---------- */
export function SearchInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <span style={{ position: "relative", display: "inline-flex", alignItems: "center" }}>
      <Search size={14} style={{ position: "absolute", left: 9, color: "var(--faint)" }} />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{ paddingLeft: 28 }}
      />
      {value ? (
        <X
          size={14}
          style={{ position: "absolute", right: 8, color: "var(--faint)", cursor: "pointer" }}
          onClick={() => onChange("")}
        />
      ) : null}
    </span>
  );
}

/* ---------- Select ---------- */
export function Select({
  value,
  onChange,
  options,
  allLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  allLabel: string;
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{allLabel}</option>
      {options.map((o) => (
        <option key={o} value={o}>{o}</option>
      ))}
    </select>
  );
}

/* ---------- Chip group (multi-select) ---------- */
export function ChipGroup<T extends string>({
  label,
  options,
  selected,
  onToggle,
  counts,
}: {
  label: string;
  options: T[];
  selected: T[];
  onToggle: (v: T) => void;
  counts?: Record<string, number>;
}) {
  return (
    <span className="chiprow">
      <span className="label">{label}</span>
      {options.map((o) => {
        const on = selected.includes(o);
        return (
          <button
            key={o}
            className={`chip ${on ? "on" : ""}`}
            onClick={() => onToggle(o)}
          >
            {o}
            {counts && counts[o] != null ? <span className="n">{counts[o]}</span> : null}
          </button>
        );
      })}
    </span>
  );
}

/* ---------- generic multi-filter helper ---------- */
export function useFilters<T>(items: T[], get: (t: T) => Record<string, string>) {
  const [search, setSearch] = useState("");
  const [sev, setSev] = useState<string[]>([]);
  const [status, setStatus] = useState<string[]>([]);
  const [phase, setPhase] = useState("");
  const [tool, setTool] = useState("");
  const [sort, setSort] = useState("");

  const toggle = (list: string[], v: string, set: (x: string[]) => void) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((t) => {
      const g = get(t);
      if (q && !Object.values(g).some((v) => v?.toLowerCase().includes(q))) return false;
      if (sev.length && !sev.includes(g.severity ?? "")) return false;
      if (status.length && !status.includes(g.status ?? "")) return false;
      if (phase && g.phase !== phase) return false;
      if (tool && g.tool !== tool) return false;
      return true;
    });
  }, [items, search, sev, status, phase, tool, get]);

  return {
    search, setSearch, sev, setSev, status, setStatus,
    phase, setPhase, tool, setTool, sort, setSort, filtered,
    toggleSev: (v: string) => toggle(sev, v, setSev),
    toggleStatus: (v: string) => toggle(status, v, setStatus),
    reset: () => { setSearch(""); setSev([]); setStatus([]); setPhase(""); setTool(""); },
    active: search !== "" || sev.length > 0 || status.length > 0 || phase !== "" || tool !== "",
  };
}
