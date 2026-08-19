import { useMemo, useState } from "react";
import type { DashboardState, AssetItem } from "../types";
import { SearchInput, EmptyState } from "../components/ui";

const KIND_LABELS: Record<string, string> = {
  subdomain: "Subdomains",
  endpoint: "Endpoints",
  url: "URLs",
  technology: "Technologies",
  open_port: "Open ports",
  host: "Hosts",
  ip: "IPs",
  service: "Services",
  sink_candidate: "JS sinks",
  js: "JS files",
};

export function Assets({ state }: { state: DashboardState }) {
  const items = state.assets_detail?.items ?? {};
  const counts = state.assets_detail?.counts ?? {};
  const kinds = Object.keys(items).sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0));
  const [kind, setKind] = useState<string>(kinds[0] ?? "url");
  const [search, setSearch] = useState("");
  const [host, setHost] = useState("");

  const list = items[kind] ?? [];
  const hosts = useMemo(
    () => [...new Set(list.map((i) => i.host).filter(Boolean))].sort() as string[],
    [list],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return list.filter((i) => {
      if (q && !String(i.value).toLowerCase().includes(q) &&
          !String(i.source ?? "").toLowerCase().includes(q)) return false;
      if (host && i.host !== host) return false;
      return true;
    });
  }, [list, search, host]);

  if (!kinds.length) {
    return <EmptyState><b>No assets discovered yet.</b><br />Run recon/probe/endpoints — subdomains, endpoints, urls and ports land here.</EmptyState>;
  }

  const effective = kinds.includes(kind) ? kind : kinds[0];

  return (
    <div>
      <div className="tabs">
        {kinds.map((k) => (
          <button key={k} className={`tab ${k === effective ? "on" : ""}`} onClick={() => setKind(k)}>
            {KIND_LABELS[k] ?? k} <span className="n">{counts[k]}</span>
          </button>
        ))}
      </div>

      <div className="filterbar">
        <SearchInput value={search} onChange={setSearch} placeholder={`search ${KIND_LABELS[effective] ?? effective}…`} />
        <select className="select-ws" value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">all hosts</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <span style={{ marginLeft: "auto", color: "var(--faint)", fontSize: 12 }}>
          {filtered.length} / {list.length}
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState><b>Nothing matches.</b><br />Adjust the search or host filter.</EmptyState>
      ) : (
        <div className="tbl-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Value</th>
                {effective === "open_port" || effective === "service" ? <th>Host</th> : null}
                <th>Source</th>
                <th>Tags</th>
                <th>First seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((i: AssetItem, idx: number) => (
                <tr key={`${i.value}-${idx}`}>
                  <td className="mono" style={{ wordBreak: "break-all" }}>{i.value}</td>
                  {effective === "open_port" || effective === "service" ? <td className="mono">{i.host ?? "—"}</td> : null}
                  <td className="mono">{i.source ?? "—"}</td>
                  <td>
                    {(i.tags ?? []).slice(0, 4).map((t) => (
                      <span key={t} className="chip" style={{ cursor: "default", marginRight: 4, marginBottom: 2, fontSize: 11 }}>{t}</span>
                    ))}
                  </td>
                  <td className="mono" style={{ color: "var(--faint)" }}>{(i.first_seen ?? "").slice(0, 19).replace("T", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
