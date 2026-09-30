import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";

export interface RuleExclusion {
  rule: number;
  domain?: string;
  path?: string;
  note?: string;
}

const reDomain =
  /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
const rePath = /^\/[A-Za-z0-9._~/-]*$/;

/** Checks one exclusion the way the agent does (it drops invalid ones). */
export function exclusionError(e: RuleExclusion): string | null {
  if (!Number.isInteger(e.rule) || e.rule <= 0 || e.rule > 99999999)
    return "Enter a numeric rule id";
  if (e.domain && !reDomain.test(e.domain))
    return "Enter a domain like example.com or *.example.com";
  if (e.path && !rePath.test(e.path))
    return "Enter a path starting with / (letters, digits, . _ ~ - / only)";
  return null;
}

/** The path part of a request URI, as an exclusion path. */
export function uriPath(uri: string): string {
  const p = (uri || "/").split("?")[0].split("#")[0];
  return rePath.test(p) ? p : "";
}

/** Per-website rule exclusions: one rule switched off for one website
 *  (and path) instead of everywhere. */
export function RuleExclusionsEditor({
  items,
  domains,
  disabled,
  vendor,
  onChange,
}: {
  items: RuleExclusion[];
  domains?: string[];
  disabled: boolean;
  vendor?: string;
  onChange: (v: RuleExclusion[]) => void;
}) {
  const [rule, setRule] = useState("");
  const [domain, setDomain] = useState("");
  const [path, setPath] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const add = () => {
    const e: RuleExclusion = {
      rule: Number(rule),
      domain: domain.trim().toLowerCase() || undefined,
      path: path.trim() || undefined,
      note: note.trim() || undefined,
    };
    const bad = exclusionError(e);
    if (bad) return setErr(bad);
    setErr("");
    onChange([...items, e]);
    setRule("");
    setPath("");
    setNote("");
  };
  return (
    <div className="border-b border-slate-100 py-4">
      <div className="font-medium text-navy-900">
        Rule exclusions per website
      </div>
      <p className="mb-3 text-sm text-slate-500">
        Switch one rule off only where it blocks something legitimate (a
        website, or a path of it), instead of for every website. Works for
        xPGuard's rules, the OWASP Core Rule Set
        {vendor ? ` and ${vendor}` : " and vendor rules"}. WAF Logs has an
        "Allow on this site" button that fills this in from a blocked request.
        WordPress admin screens of logged-in users and writes to WordPress's own
        REST API are already exempt from the injection rules (rules
        7700010–7700012).
      </p>
      {items.length > 0 && (
        <div className="mb-3 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="py-1 pr-3">Rule</th>
                <th className="pr-3">Website</th>
                <th className="pr-3">Path</th>
                <th className="pr-3">Note</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((e, i) => (
                <tr key={`${e.rule}-${e.domain}-${e.path}-${i}`}>
                  <td className="py-2 pr-3 font-mono text-xs">{e.rule}</td>
                  <td className="pr-3">
                    {e.domain || (
                      <span className="text-slate-400">all websites</span>
                    )}
                  </td>
                  <td className="pr-3 font-mono text-xs break-all">
                    {e.path || (
                      <span className="font-sans text-slate-400">
                        whole site
                      </span>
                    )}
                  </td>
                  <td className="pr-3 text-xs text-slate-500">{e.note}</td>
                  <td className="text-right">
                    <button
                      className="text-slate-400 hover:text-red-600"
                      title="Remove"
                      disabled={disabled}
                      onClick={() => onChange(items.filter((_, j) => j !== i))}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <div className="label">Rule id</div>
          <input
            className="input w-28"
            inputMode="numeric"
            placeholder="941100"
            value={rule}
            disabled={disabled}
            onChange={(e) => setRule(e.target.value.replace(/\D/g, ""))}
          />
        </label>
        <label className="text-sm">
          <div className="label">Website</div>
          <input
            className="input w-56"
            list="xg-excl-domains"
            placeholder="all websites"
            value={domain}
            disabled={disabled}
            onChange={(e) => setDomain(e.target.value)}
          />
          <datalist id="xg-excl-domains">
            {(domains ?? []).map((d) => (
              <option key={d} value={d} />
            ))}
          </datalist>
        </label>
        <label className="text-sm">
          <div className="label">Path starts with</div>
          <input
            className="input w-56"
            placeholder="/wp-admin/admin.php"
            value={path}
            disabled={disabled}
            onChange={(e) => setPath(e.target.value)}
          />
        </label>
        <label className="text-sm">
          <div className="label">Note</div>
          <input
            className="input w-48"
            placeholder="why"
            value={note}
            disabled={disabled}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
        <button
          className="btn-primary"
          disabled={disabled || !rule}
          onClick={add}
        >
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>
      {err && <p className="mt-2 text-sm text-red-600">{err}</p>}
    </div>
  );
}
