import { Fragment, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Archive,
  ChevronDown,
  ChevronRight,
  Database,
  Download,
  RefreshCw,
  RotateCcw,
  Search,
  Sparkles,
} from "lucide-react";
import { can, useAuth } from "../auth";
import {
  Breadcrumb,
  Empty,
  ErrorBox,
  PageLoader,
  SectionLoader,
  StatCard,
} from "../components/ui";
import {
  Modal,
  Pager,
  agentCall,
  fmtTime,
  useAction,
  useAgent,
} from "../components/controls";
import { useServerName } from "./Scanner";

interface Component {
  slug: string;
  name: string;
  version: string;
  latest: string;
  outdated: boolean;
}

interface Site {
  id: number;
  type: "wordpress" | "joomla" | "opencart";
  path: string;
  user: string;
  domain: string;
  version: string;
  latest: string;
  plugins: Component[];
  themes: Component[];
  mu_plugins: string[];
  outdated_plugins: number;
  outdated_themes: number;
  core: {
    checked: number;
    modified: string[];
    unknown: string[];
    error?: string;
  };
  core_issues: number;
  db_issues: number;
  risk: "critical" | "high" | "medium" | "ok";
  scanned_at: number;
}

interface BulkStatus {
  running: boolean;
  mode: string;
  sites: number;
  done: number;
  updated: number;
  failed: number;
  current: string;
  started: number;
  finished: number;
  errors?: string[];
}

interface CmsStatus {
  status: { running: boolean; last_scan: number; error: string };
  bulk?: BulkStatus;
  scan_requested?: boolean;
  counts: {
    with_issues: number;
    wordpress: number;
    joomla: number;
    opencart: number;
    outdated: number;
    db_infected: number;
  };
}

const RISK: Record<string, string> = {
  critical: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  medium: "bg-amber-100 text-amber-700",
  ok: "bg-green-100 text-green-700",
};

const TYPE_LABEL: Record<string, string> = {
  wordpress: "WordPress",
  joomla: "Joomla",
  opencart: "OpenCart",
};

function RiskBadge({ risk }: { risk: string }) {
  return (
    <span
      className={`rounded-full px-3 py-1 text-xs font-medium capitalize ${RISK[risk] ?? ""}`}
    >
      {risk === "ok" ? "Secure" : risk}
    </span>
  );
}

export function CMSThreats() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const [risk, setRisk] = useState("");
  const [account, setAccount] = useState("");
  const [accountQ, setAccountQ] = useState("");
  const [sel, setSel] = useState<string[]>([]);
  const [scope, setScope] = useState<"selected" | "account" | "all">(
    "selected",
  );
  const limit = 25;
  const status = useAgent<CmsStatus>(id, "cms.status", {}, 5000);
  const list = useAgent<{ sites: Site[]; total: number }>(id, "cms.sites", {
    type,
    risk,
    account,
    q: query,
    limit,
    offset,
  });
  const { run, busy } = useAction();
  const running = status.data?.status.running;
  // A scan that just finished found new sites: show them.
  const wasRunning = useRef(running);
  useEffect(() => {
    if (wasRunning.current && !running) list.reload();
    wasRunning.current = running;
  }, [running]); // eslint-disable-line react-hooks/exhaustive-deps
  // Another filter: the selection is of sites no longer shown.
  useEffect(() => setSel([]), [type, risk, account, query]);

  if (status.loading && !status.data) return <PageLoader />;
  if (status.error && !status.data) return <ErrorBox message={status.error} />;
  const c = status.data!.counts;

  const update = async (s: Site, what: string, slug = "") => {
    const label =
      what === "core-repair"
        ? "Reinstall the official WordPress core files"
        : `Update ${slug || "WordPress core"}`;
    if (!confirm(`${label} on ${s.domain || s.path}?`)) return;
    const r = await run(
      () =>
        agentCall<{ output: string }>(id!, "cms.update", {
          path: s.path,
          what,
          slug,
        }),
      "Done",
    );
    if (r) list.reload();
  };

  const bulk = status.data?.bulk;
  const bulkRunning = !!bulk?.running;
  const startBulk = async (mode: "vulnerable" | "outdated") => {
    const what =
      mode === "vulnerable"
        ? "every plugin and theme with a known vulnerability (and WordPress core to its security release)"
        : "every outdated plugin and theme (and WordPress core to the latest release of its branch)";
    const where =
      scope === "selected"
        ? `${sel.length} selected site${sel.length === 1 ? "" : "s"}`
        : scope === "account"
          ? `all WordPress sites of the account ${account}`
          : "ALL WordPress sites on this server";
    if (
      !confirm(
        `Update ${what} on ${where}?\n\nUpdates can change how a site works; make sure backups exist.`,
      )
    )
      return;
    const params: Record<string, unknown> = { mode };
    if (scope === "selected") params.paths = sel;
    if (scope === "account") params.account = account;
    const r = await run(
      () => agentCall<{ sites: number }>(id!, "cms.bulk_update", params),
      "Bulk update started",
    );
    if (r) {
      setSel([]);
      status.reload();
    }
  };
  const pageSites = list.data?.sites ?? [];
  const allOnPage =
    pageSites.length > 0 && pageSites.every((s) => sel.includes(s.path));

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, "CMS threats"]} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={<Database />}
          value={c.with_issues}
          label="CMS with issues"
          accent={c.with_issues ? "text-red-600" : "text-green-600"}
        />
        <StatCard
          icon={<span className="text-lg font-bold">W</span>}
          value={c.wordpress}
          label="WordPress installations"
        />
        <StatCard
          icon={<span className="text-lg font-bold">J</span>}
          value={c.joomla}
          label="Joomla installations"
        />
        <StatCard
          icon={<span className="text-lg font-bold">OC</span>}
          value={c.opencart}
          label="OpenCart installations"
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">CMS Threat Alerts</h1>
          <p className="text-sm text-slate-500">
            {running
              ? bulk?.running
                ? "Updating websites…"
                : "Scanning websites (slowly)…"
              : status.data!.status.last_scan
                ? `Last scan ${fmtTime(status.data!.status.last_scan)}`
                : "Not scanned yet"}
            {status.data!.status.error && (
              <span className="text-red-600">
                {" "}
                · {status.data!.status.error}
              </span>
            )}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="input w-36"
            value={risk}
            onChange={(e) => (setOffset(0), setRisk(e.target.value))}
          >
            <option value="">All risks</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="ok">Secure</option>
          </select>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setOffset(0);
              setAccount(accountQ.trim());
            }}
          >
            <input
              className="input w-40"
              placeholder="Account (cPanel user)"
              value={accountQ}
              onChange={(e) => setAccountQ(e.target.value)}
            />
          </form>
          <select
            className="input w-40"
            value={type}
            onChange={(e) => (setOffset(0), setType(e.target.value))}
          >
            <option value="">All CMS</option>
            <option value="wordpress">WordPress</option>
            <option value="joomla">Joomla</option>
            <option value="opencart">OpenCart</option>
          </select>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setOffset(0);
              setQuery(q.trim());
            }}
          >
            <input
              className="input w-52"
              placeholder="Type to filter"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <button className="btn-outline">
              <Search className="h-4 w-4" />
            </button>
          </form>
          {can(user, "operator") && (
            <button
              className="btn-primary"
              disabled={busy || running}
              title="Every website is checked tonight from 2:00 (scan schedule time zone), slowly, so the websites do not feel it"
              onClick={() =>
                run(
                  () => agentCall<{ at: number }>(id!, "cms.scan"),
                  "Full scan queued for tonight (2:00)",
                ).then(() => status.reload())
              }
            >
              <RefreshCw
                className={`h-4 w-4 ${running ? "animate-spin" : ""}`}
              />{" "}
              {status.data?.scan_requested ? "Queued for tonight" : "Scan tonight"}
            </button>
          )}
        </div>
      </div>

      {can(user, "admin") && (
        <div className="card flex flex-wrap items-center gap-3 py-3 text-sm">
          <span className="font-medium text-navy-900">Bulk update</span>
          <select
            className="input w-64"
            value={scope}
            onChange={(e) => setScope(e.target.value as typeof scope)}
          >
            <option value="selected">Selected sites ({sel.length})</option>
            <option value="account" disabled={!account}>
              {account
                ? `All sites of account ${account}`
                : "All sites of an account (filter by account first)"}
            </option>
            <option value="all">All WordPress sites on this server</option>
          </select>
          <button
            className="btn-primary"
            disabled={
              busy ||
              bulkRunning ||
              running ||
              (scope === "selected" && sel.length === 0)
            }
            onClick={() => startBulk("vulnerable")}
            title="Plugins and themes with a known vulnerability; WordPress core to its security release"
          >
            Update vulnerable
          </button>
          <button
            className="btn-outline"
            disabled={
              busy ||
              bulkRunning ||
              running ||
              (scope === "selected" && sel.length === 0)
            }
            onClick={() => startBulk("outdated")}
            title="Every outdated plugin and theme; WordPress core to the latest release of its branch"
          >
            Update all outdated
          </button>
          {bulk && bulk.started > 0 && (
            <span className={bulkRunning ? "text-blue-700" : "text-slate-500"}>
              {bulkRunning
                ? `Updating ${bulk.done} of ${bulk.sites} sites… ${bulk.current.replace(/^\/home\//, "")}`
                : `Last bulk update (${bulk.mode}) ${fmtTime(bulk.finished)}: ${bulk.sites} sites, ${bulk.updated} updates`}
              {bulk.failed > 0 && (
                <span className="text-red-600" title={(bulk.errors ?? []).join("\n")}>
                  {" "}
                  · {bulk.failed} failed
                </span>
              )}
            </span>
          )}
        </div>
      )}

      <div className="card overflow-x-auto p-0">
        {!list.data ? (
          list.error ? (
            <ErrorBox message={list.error} />
          ) : (
            <SectionLoader />
          )
        ) : list.data.sites.length === 0 ? (
          <Empty
            text={
              running
                ? "Scanning…"
                : "No CMS installations found yet. Run a scan."
            }
          />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 uppercase">
              <tr>
                {can(user, "admin") && (
                  <th className="w-8 pl-4">
                    <input
                      type="checkbox"
                      aria-label="Select the sites on this page"
                      checked={allOnPage}
                      onChange={() =>
                        setSel(
                          allOnPage
                            ? sel.filter(
                                (p) => !pageSites.some((s) => s.path === p),
                              )
                            : [
                                ...new Set([
                                  ...sel,
                                  ...pageSites
                                    .filter((s) => s.type === "wordpress")
                                    .map((s) => s.path),
                                ]),
                              ],
                        )
                      }
                    />
                  </th>
                )}
                <th className="px-4 py-3">CMS</th>
                <th className="px-2">User</th>
                <th className="px-2">Version</th>
                <th className="px-2">Plugins</th>
                <th className="px-2">Themes</th>
                <th className="px-2">Issues</th>
                <th className="px-2">Risk</th>
                <th className="px-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {list.data.sites.map((s) => (
                <Fragment key={s.id}>
                  <tr
                    className="cursor-pointer hover:bg-slate-50"
                    onClick={() => setOpen(open === s.id ? null : s.id)}
                  >
                    {can(user, "admin") && (
                      <td className="pl-4" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          aria-label={`Select ${s.domain || s.path}`}
                          disabled={s.type !== "wordpress"}
                          checked={sel.includes(s.path)}
                          onChange={() =>
                            setSel(
                              sel.includes(s.path)
                                ? sel.filter((p) => p !== s.path)
                                : [...sel, s.path],
                            )
                          }
                        />
                      </td>
                    )}
                    <td className="px-4 py-3">
                      <div className="font-medium text-navy-900">
                        {s.domain || s.path.split("/").slice(-2).join("/")}
                      </div>
                      <div className="text-xs text-slate-500">
                        {TYPE_LABEL[s.type]} · {s.path.replace(/^\/home\//, "")}
                      </div>
                    </td>
                    <td className="px-2">{s.user}</td>
                    <td className="px-2">
                      {s.version || "?"}
                      {s.latest && s.version && s.version !== s.latest && (
                        <div className="text-xs text-red-600">
                          latest {s.latest}
                        </div>
                      )}
                    </td>
                    <td className="px-2">
                      {s.plugins.length}{" "}
                      {s.outdated_plugins > 0 && (
                        <span className="ml-1 rounded bg-red-50 px-1.5 text-xs text-red-600">
                          {s.outdated_plugins} outdated
                        </span>
                      )}
                    </td>
                    <td className="px-2">
                      {s.themes.length}{" "}
                      {s.outdated_themes > 0 && (
                        <span className="ml-1 rounded bg-red-50 px-1.5 text-xs text-red-600">
                          {s.outdated_themes} outdated
                        </span>
                      )}
                    </td>
                    <td className="px-2">
                      {s.core_issues + s.db_issues}
                      {s.core_issues > 0 && (
                        <div className="text-xs text-red-600">
                          {s.core_issues} core files
                        </div>
                      )}
                      {s.db_issues > 0 && (
                        <div className="text-xs text-red-600">
                          {s.db_issues} in database
                        </div>
                      )}
                    </td>
                    <td className="px-2">
                      <RiskBadge risk={s.risk} />
                    </td>
                    <td className="px-2 text-slate-400">
                      {open === s.id ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </td>
                  </tr>
                  {open === s.id && (
                    <tr>
                      <td colSpan={can(user, "admin") ? 9 : 8} className="bg-slate-50 px-4 py-4">
                        <SiteDetail
                          site={s}
                          admin={can(user, "admin")}
                          busy={busy}
                          onUpdate={update}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {list.data && (
        <Pager
          total={list.data.total}
          limit={limit}
          offset={offset}
          onChange={setOffset}
        />
      )}
      <p className="text-xs text-slate-400">
        Risk: <b>critical</b> = modified/foreign WordPress core files, database
        infection or a whole major version behind; <b>high</b> = core update
        available or 5+ outdated plugins; <b>medium</b> = outdated
        plugins/themes.
      </p>
    </div>
  );
}

function SiteDetail({
  site: s,
  admin,
  busy,
  onUpdate,
}: {
  site: Site;
  admin: boolean;
  busy: boolean;
  onUpdate: (s: Site, what: string, slug?: string) => void;
}) {
  const wp = s.type === "wordpress";
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <div>
        <h3 className="mb-2 font-semibold text-navy-900">Core</h3>
        <div className="text-sm">
          Version {s.version || "?"}
          {s.latest && ` (latest ${s.latest})`}
          {admin && wp && s.latest && s.version !== s.latest && (
            <button
              className="btn-outline ml-3 px-2 py-1 text-xs"
              disabled={busy}
              onClick={() => onUpdate(s, "core")}
            >
              Update core
            </button>
          )}
        </div>
        {wp && (
          <div className="mt-2 text-sm">
            {s.core.error ? (
              <span className="text-slate-500">
                Core integrity not checked: {s.core.error}
              </span>
            ) : s.core.modified.length + s.core.unknown.length === 0 ? (
              <span className="text-green-700">
                All {s.core.checked} core files match the official WordPress
                release.
              </span>
            ) : (
              <div className="rounded bg-red-50 p-3 text-red-800">
                <div className="font-medium">
                  {s.core.modified.length} modified and {s.core.unknown.length}{" "}
                  foreign files in WordPress core
                </div>
                <ul className="mt-1 max-h-40 overflow-y-auto font-mono text-xs">
                  {s.core.modified.map((f) => (
                    <li key={f}>modified: {f}</li>
                  ))}
                  {s.core.unknown.map((f) => (
                    <li key={f}>not part of WordPress: {f}</li>
                  ))}
                </ul>
                {admin && (
                  <button
                    className="btn-danger mt-2 px-2 py-1 text-xs"
                    disabled={busy}
                    onClick={() => onUpdate(s, "core-repair")}
                  >
                    Reinstall official core files
                  </button>
                )}
                <p className="mt-1 text-xs">
                  Reinstalling replaces modified files; foreign files must be
                  reviewed and removed (Manual Scans can quarantine them).
                </p>
              </div>
            )}
          </div>
        )}
        {s.mu_plugins.length > 0 && (
          <div className="mt-3 text-sm">
            <span className="font-medium">Must-use plugins</span> (always
            loaded; check they are expected):{" "}
            <span className="font-mono text-xs">{s.mu_plugins.join(", ")}</span>
          </div>
        )}
        <div className="mt-3 text-xs text-slate-500">
          Scanned {fmtTime(s.scanned_at)}
        </div>
      </div>
      {wp && (
        <div className="space-y-4">
          <ComponentTable
            title="Plugins"
            kind="plugin"
            items={s.plugins}
            site={s}
            admin={admin}
            busy={busy}
            onUpdate={onUpdate}
          />
          <ComponentTable
            title="Themes"
            kind="theme"
            items={s.themes}
            site={s}
            admin={admin}
            busy={busy}
            onUpdate={onUpdate}
          />
        </div>
      )}
    </div>
  );
}

function ComponentTable({
  title,
  kind,
  items,
  site,
  admin,
  busy,
  onUpdate,
}: {
  title: string;
  kind: string;
  items: Component[];
  site: Site;
  admin: boolean;
  busy: boolean;
  onUpdate: (s: Site, what: string, slug?: string) => void;
}) {
  return (
    <div>
      <h3 className="mb-1 font-semibold text-navy-900">{title}</h3>
      {items.length === 0 ? (
        <div className="text-sm text-slate-400">None</div>
      ) : (
        <table className="w-full text-sm">
          <tbody className="divide-y divide-slate-200">
            {items.map((c) => (
              <tr key={c.slug}>
                <td className="py-1.5">
                  {c.name}{" "}
                  <span className="text-xs text-slate-400">({c.slug})</span>
                </td>
                <td className="py-1.5 text-xs">
                  {c.version || "?"}
                  {c.outdated && (
                    <span className="ml-1 text-red-600">→ {c.latest}</span>
                  )}
                  {!c.latest && (
                    <span className="ml-1 text-slate-400">
                      not on wordpress.org
                    </span>
                  )}
                </td>
                <td className="py-1.5 text-right">
                  {admin && c.outdated && (
                    <button
                      className="btn-outline px-2 py-0.5 text-xs"
                      disabled={busy}
                      onClick={() => onUpdate(site, kind, c.slug)}
                    >
                      Update
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

interface DBRow {
  id: number;
  at: number;
  site_path: string;
  user: string;
  database: string;
  table: string;
  row: string;
  signature: string;
  status: string;
  column?: string;
  category?: string;
  snippet?: string;
  first_seen?: number;
  note?: string;
  restorable?: boolean;
}

interface DBCleanResult {
  id: number;
  ok: boolean;
  action?: string;
  error?: string;
}

const DB_CATEGORY: Record<string, string> = {
  script: "Injected script",
  iframe: "Hidden iframe",
  php: "PHP code in the database",
  siteurl: "Site URL changed",
};

function dbCSV(rows: DBRow[]): string {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = [
    "database",
    "table",
    "key",
    "column",
    "category",
    "signature",
    "snippet",
    "user",
    "site",
    "status",
    "first_seen",
    "last_seen",
  ];
  return [
    head.join(","),
    ...rows.map((r) =>
      [
        r.database,
        r.table,
        r.row,
        r.column,
        r.category,
        r.signature,
        r.snippet,
        r.user,
        r.site_path,
        r.status,
        r.first_seen ? new Date(r.first_seen * 1000).toISOString() : "",
        new Date(r.at * 1000).toISOString(),
      ]
        .map(esc)
        .join(","),
    ),
  ].join("\n");
}

export function DBScanner() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [status, setStatus] = useState("detected");
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(25);
  const [sel, setSel] = useState<number[]>([]);
  const [detail, setDetail] = useState<DBRow | null>(null);
  const [exporting, setExporting] = useState(false);
  const [failed, setFailed] = useState<
    { row?: DBRow; id: number; error: string }[]
  >([]);
  const list = useAgent<{ findings: DBRow[]; total: number }>(
    id,
    "db.findings",
    { status, q: query, limit, offset },
  );
  const { run, busy } = useAction();
  const rows = list.data?.findings ?? [];
  const selRows = rows.filter((r) => sel.includes(r.id));

  // Clean or restore in batches; rows that could not be done are listed.
  const bulk = async (action: "db.clean" | "db.restore", ids: number[]) => {
    const verb = action === "db.clean" ? "cleaned" : "restored";
    const text =
      action === "db.clean"
        ? `Clean ${ids.length} database finding(s)? Only the injected code is cut out of each row; the rest of the row stays, and the old value is saved so it can be restored.`
        : `Put back the saved value of ${ids.length} cleaned finding(s)? The injected code returns to those rows.`;
    if (!confirm(text)) return;
    const r = await run(
      async () => {
        const results: DBCleanResult[] = [];
        for (let i = 0; i < ids.length; i += 200) {
          const part = await agentCall<{ results: DBCleanResult[] }>(
            id!,
            action,
            { ids: ids.slice(i, i + 200) },
          );
          results.push(...part.results);
        }
        return results;
      },
      (res) => {
        const ok = res.filter((x) => x.ok).length;
        return (
          `${ok} ${verb}` +
          (ok < res.length ? `, ${res.length - ok} not (see the list)` : "")
        );
      },
    );
    if (r) {
      setFailed(
        r
          .filter((x) => !x.ok)
          .map((x) => ({
            id: x.id,
            error: x.error || "failed",
            row: rows.find((f) => f.id === x.id),
          })),
      );
      setSel([]);
      list.reload();
    }
  };

  // Every finding of the current filter, not only this page.
  const cleanAll = async () => {
    const ids: number[] = [];
    try {
      for (let off = 0; off < (list.data?.total ?? 0); off += 1000) {
        const r = await agentCall<{ findings: DBRow[] }>(id!, "db.findings", {
          status,
          q: query,
          limit: 1000,
          offset: off,
        });
        ids.push(...r.findings.map((f) => f.id));
        if (r.findings.length < 1000) break;
      }
    } catch (e: any) {
      alert(e.message || "Could not list the findings");
      return;
    }
    if (ids.length) await bulk("db.clean", ids);
  };

  const exportAll = async () => {
    setExporting(true);
    try {
      const all: DBRow[] = [];
      for (let off = 0; off < (list.data?.total ?? 0); off += 1000) {
        const r = await agentCall<{ findings: DBRow[] }>(id!, "db.findings", {
          status,
          q: query,
          limit: 1000,
          offset: off,
        });
        all.push(...r.findings);
        if (r.findings.length < 1000) break;
      }
      const a = document.createElement("a");
      a.href = URL.createObjectURL(
        new Blob([dbCSV(all)], { type: "text/csv" }),
      );
      a.download = `db-scanner-${host}-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
    } catch (e: any) {
      alert(e.message || "Export failed");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, "DB Scanner"]} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">DB Scanner Logs</h1>
          <p className="text-sm text-slate-500">
            WordPress databases (options, posts, post meta) are scanned daily
            for injected scripts, hidden iframes, PHP code and a changed site
            URL. Click a row to see what was found.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="input w-36"
            value={status}
            onChange={(e) => (
              setOffset(0),
              setSel([]),
              setStatus(e.target.value)
            )}
          >
            <option value="detected">Detected</option>
            <option value="cleaned">Cleaned</option>
            <option value="cleared">False positive</option>
            <option value="archived">Archived</option>
            <option value="">All</option>
          </select>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setOffset(0);
              setQuery(q.trim());
            }}
          >
            <input
              className="input w-52"
              placeholder="Type to filter"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <button className="btn-outline">
              <Search className="h-4 w-4" />
            </button>
          </form>
          <button
            className="btn-outline"
            title="Export all matching entries (CSV)"
            onClick={exportAll}
            disabled={!list.data?.total || exporting}
          >
            <Download className="h-4 w-4" />
          </button>
          {can(user, "operator") && (
            <>
              {(status === "detected" || status === "archived") && (
                <>
                  <button
                    className="btn-primary"
                    title="Cut the injected code out of the selected rows (the old value is saved)"
                    disabled={busy || sel.length === 0}
                    onClick={() => bulk("db.clean", sel)}
                  >
                    <Sparkles className="h-4 w-4" /> Clean selected
                  </button>
                  <button
                    className="btn-outline"
                    title="Clean every finding of this list, on all pages"
                    disabled={busy || !list.data?.total}
                    onClick={cleanAll}
                  >
                    <Sparkles className="h-4 w-4" /> Clean all (
                    {list.data?.total ?? 0})
                  </button>
                </>
              )}
              {status === "cleaned" && (
                <button
                  className="btn-outline"
                  title="Put back the value saved before xPGuard cleaned the row"
                  disabled={busy || !selRows.some((r) => r.restorable)}
                  onClick={() =>
                    bulk(
                      "db.restore",
                      selRows.filter((r) => r.restorable).map((r) => r.id),
                    )
                  }
                >
                  <RotateCcw className="h-4 w-4" /> Restore
                </button>
              )}
              <button
                className="btn-outline"
                disabled={busy || sel.length === 0}
                onClick={() =>
                  run(
                    () => agentCall(id!, "db.archive", { ids: sel }),
                    `${sel.length} archived`,
                  ).then(() => {
                    setSel([]);
                    list.reload();
                  })
                }
              >
                <Archive className="h-4 w-4" /> Archive
              </button>
            </>
          )}
        </div>
      </div>
      {failed.length > 0 && (
        <div className="card border-amber-200 bg-amber-50 text-sm">
          <div className="flex items-center justify-between">
            <div className="font-medium text-amber-900">
              {failed.length} could not be done automatically
            </div>
            <button
              className="text-xs text-amber-800 underline"
              onClick={() => setFailed([])}
            >
              Hide
            </button>
          </div>
          <ul className="mt-2 max-h-48 space-y-1 overflow-auto text-xs text-amber-900">
            {failed.map((f) => (
              <li key={f.id}>
                <span className="font-mono">
                  {f.row
                    ? `${f.row.database} » ${f.row.table} ${f.row.row}`
                    : `#${f.id}`}
                </span>
                : {f.error}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="card overflow-hidden p-0">
        {!list.data ? (
          list.error ? (
            <ErrorBox message={list.error} />
          ) : (
            <SectionLoader />
          )
        ) : rows.length === 0 ? (
          <Empty text="No records to display" />
        ) : (
          <div className="max-h-[70vh] overflow-auto">
            <table className="w-full min-w-[980px] text-sm">
              <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500 uppercase shadow-[0_1px_0_#e2e8f0]">
                <tr>
                  <th className="w-12 px-4 py-3">
                    <input
                      type="checkbox"
                      className="h-4 w-4"
                      checked={
                        rows.length > 0 && rows.every((r) => sel.includes(r.id))
                      }
                      onChange={(e) =>
                        setSel(e.target.checked ? rows.map((f) => f.id) : [])
                      }
                    />
                  </th>
                  <th className="px-2">Database / table</th>
                  <th className="px-2">Found</th>
                  <th className="px-2">What was found</th>
                  <th className="px-2">Account</th>
                  <th className="px-2">Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {rows.map((f) => (
                  <tr
                    key={f.id}
                    className={`cursor-pointer align-top hover:bg-slate-50 ${sel.includes(f.id) ? "bg-sky-50/60" : ""}`}
                    onClick={() => setDetail(f)}
                  >
                    <td
                      className="px-4 py-3"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <input
                        type="checkbox"
                        className="h-4 w-4"
                        checked={sel.includes(f.id)}
                        onChange={(e) =>
                          setSel(
                            e.target.checked
                              ? [...sel, f.id]
                              : sel.filter((x) => x !== f.id),
                          )
                        }
                      />
                    </td>
                    <td className="px-2 py-3 font-mono text-xs">
                      {f.database}
                      <div className="text-slate-500">
                        {f.table}
                        {f.column ? `.${f.column}` : ""}
                      </div>
                      <div className="text-slate-400">{f.row}</div>
                    </td>
                    <td className="px-2 py-3">
                      <div
                        className={
                          f.status === "detected"
                            ? "text-red-700"
                            : "text-slate-600"
                        }
                      >
                        {f.signature}
                      </div>
                      {f.note && (
                        <div className="text-xs text-emerald-700">{f.note}</div>
                      )}
                      {f.category && (
                        <div className="text-xs text-slate-500">
                          {DB_CATEGORY[f.category] ?? f.category}
                        </div>
                      )}
                    </td>
                    <td className="max-w-md px-2 py-3">
                      {f.snippet ? (
                        <code className="line-clamp-2 block rounded bg-slate-50 px-2 py-1 text-xs break-all text-slate-700">
                          {f.snippet}
                        </code>
                      ) : (
                        <span className="text-xs text-slate-400">
                          detected before 0.7.9 (rescan to see the code)
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-3">
                      {f.user}
                      <div className="text-xs text-slate-400">
                        {f.site_path}
                      </div>
                    </td>
                    <td className="px-2 py-3 text-xs whitespace-nowrap text-slate-500">
                      {f.first_seen ? (
                        <div>first {fmtTime(f.first_seen)}</div>
                      ) : null}
                      <div>last {fmtTime(f.at)}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {list.data && (
        <div className="flex flex-wrap items-center justify-end gap-3 text-sm">
          <label className="flex items-center gap-2 text-slate-500">
            Items per page
            <select
              className="input w-24"
              value={limit}
              onChange={(e) => (
                setOffset(0),
                setSel([]),
                setLimit(Number(e.target.value))
              )}
            >
              {[25, 50, 100, 200].map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
          <Pager
            total={list.data.total}
            limit={limit}
            offset={offset}
            onChange={(o) => (setSel([]), setOffset(o))}
          />
        </div>
      )}
      {detail && (
        <Modal title="Database finding" onClose={() => setDetail(null)} wide>
          <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm sm:grid-cols-[150px_minmax(0,1fr)]">
            {(
              [
                ["Signature", detail.signature],
                [
                  "Kind",
                  detail.category
                    ? (DB_CATEGORY[detail.category] ?? detail.category)
                    : "–",
                ],
                ["Database", detail.database],
                [
                  "Table / column",
                  `${detail.table}${detail.column ? "." + detail.column : ""}`,
                ],
                ["Row", detail.row],
                ["Account", `${detail.user} · ${detail.site_path}`],
                [
                  "Status",
                  detail.note
                    ? `${detail.status} – ${detail.note}`
                    : detail.status,
                ],
                [
                  "First seen",
                  detail.first_seen ? fmtTime(detail.first_seen) : "–",
                ],
                ["Last seen", fmtTime(detail.at)],
              ] as [string, string][]
            ).map(([k, v]) => (
              <Fragment key={k}>
                <dt className="text-slate-500">{k}</dt>
                <dd className="font-mono break-all text-navy-900">{v}</dd>
              </Fragment>
            ))}
          </dl>
          <div className="mt-4">
            <div className="mb-1 text-sm font-medium text-navy-900">
              Matching content
            </div>
            <pre className="max-h-72 overflow-auto rounded-lg bg-navy-950 p-3 text-xs break-all whitespace-pre-wrap text-slate-100">
              {detail.snippet ||
                "Not recorded (found before 0.7.9). It is recorded at the next DB scan."}
            </pre>
            <p className="mt-2 text-xs text-slate-500">
              Clean selected cuts this code out of {detail.database} »{" "}
              {detail.table}, {detail.row} and keeps the rest of the row; the
              old value is saved and can be restored. Clear a page cache or
              object cache plugin afterwards so visitors get the cleaned page.
              The code that wrote it (a file, a stolen admin login) must be
              found too, or it comes back.
            </p>
          </div>
        </Modal>
      )}
    </div>
  );
}
