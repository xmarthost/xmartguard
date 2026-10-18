import { useState } from 'react';
import { AlertTriangle, Layers, PlayCircle } from 'lucide-react';
import { Modal, agentCall, fmtTime, useAction, useAgent } from './controls';

interface Sample {
  id: number;
  path: string;
  owner: string;
  status: string;
  updated_at: number;
}

/** "datetime-local" value for a unix time. */
const local = (t: number) => {
  const d = new Date(t * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
};
const unix = (v: string) => (v ? Math.floor(new Date(v).getTime() / 1000) : 0);

/** Restore (or quarantine) every file of one signature in a time window,
 *  after a preview. */
export function BulkFindings({ serverId, signature: sig0 = '', action: act0 = 'restore', onClose, onDone }: {
  serverId: string;
  signature?: string;
  action?: 'restore' | 'quarantine';
  onClose: () => void;
  onDone: () => void;
}) {
  const now = Math.floor(Date.now() / 1000);
  const [signature, setSignature] = useState(sig0);
  const [action, setAction] = useState<'restore' | 'quarantine'>(act0);
  const [from, setFrom] = useState(local(now - 86400));
  const [to, setTo] = useState('');
  const [owner, setOwner] = useState('');
  const [preview, setPreview] = useState<{ total: number; sample: Sample[] } | null>(null);
  const { run, busy } = useAction();
  const filter = () => ({ signature: signature.trim(), action, from: unix(from), to: unix(to), owner: owner.trim() });
  const changed = () => setPreview(null);

  return (
    <Modal title="Bulk restore or quarantine" onClose={onClose} wide>
      <p className="mb-4 text-sm text-slate-500">
        Every file one signature detected in a time window, for example everything a wrong signature quarantined last night. Preview first; restored files are
        remembered as clean and not flagged again until they change.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm sm:col-span-2">
          <span className="label">Signature</span>
          <input className="input font-mono" value={signature} onChange={(e) => (setSignature(e.target.value), changed())} placeholder="e.g. PHP.Backdoor.Eval" />
        </label>
        <label className="text-sm">
          <span className="label">Action</span>
          <select className="input" value={action} onChange={(e) => (setAction(e.target.value as 'restore'), changed())}>
            <option value="restore">Restore quarantined / disabled files</option>
            <option value="quarantine">Quarantine files still waiting or restored by the AI</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="label">Account (optional)</span>
          <input className="input" value={owner} onChange={(e) => (setOwner(e.target.value), changed())} placeholder="all accounts" />
        </label>
        <label className="text-sm">
          <span className="label">From</span>
          <input type="datetime-local" className="input" value={from} onChange={(e) => (setFrom(e.target.value), changed())} />
        </label>
        <label className="text-sm">
          <span className="label">To (empty = now)</span>
          <input type="datetime-local" className="input" value={to} onChange={(e) => (setTo(e.target.value), changed())} />
        </label>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <button
          className="btn-outline"
          disabled={busy || !signature.trim()}
          onClick={() => run(() => agentCall<{ total: number; sample: Sample[] }>(serverId, 'findings.bulk', { ...filter(), preview: true }).then(setPreview))}
        >
          <Layers className="h-4 w-4" /> Preview
        </button>
        {preview && preview.total > 0 && (
          <button
            className="btn-primary"
            disabled={busy}
            onClick={async () => {
              if (!confirm(`${action === 'restore' ? 'Restore' : 'Quarantine'} ${preview.total.toLocaleString()} file(s)?`)) return;
              const r = await run(
                () => agentCall<{ done: number; failed: number; errors?: string[] }>(serverId, 'findings.bulk', filter()),
                (r) => `${r.done.toLocaleString()} done${r.failed ? `, ${r.failed} failed` : ''}`,
              );
              if (r?.errors?.length) alert(r.errors.join('\n'));
              if (r) {
                onDone();
                onClose();
              }
            }}
          >
            <PlayCircle className="h-4 w-4" /> {action === 'restore' ? 'Restore' : 'Quarantine'} {preview.total.toLocaleString()} file(s)
          </button>
        )}
      </div>
      {preview && (
        <div className="mt-4">
          {preview.total === 0 ? (
            <p className="text-sm text-slate-500">No file matches.</p>
          ) : (
            <>
              <p className="mb-2 text-sm text-slate-600">
                {preview.total.toLocaleString()} file(s){preview.total > preview.sample.length && `, the newest ${preview.sample.length} shown`}:
              </p>
              <div className="max-h-72 overflow-auto rounded-lg border border-slate-200">
                <table className="w-full text-left text-xs">
                  <tbody className="divide-y divide-slate-100">
                    {preview.sample.map((f) => (
                      <tr key={f.id}>
                        <td className="px-3 py-1.5 font-mono break-all">{f.path}</td>
                        <td className="px-3 py-1.5">{f.owner}</td>
                        <td className="px-3 py-1.5">{f.status}</td>
                        <td className="px-3 py-1.5 whitespace-nowrap">{fmtTime(f.updated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </Modal>
  );
}

interface Paused {
  signature: string;
  at: number;
  files: number;
}

/** Signatures paused after quarantining too many files at once. */
export function PausedSignatures({ serverId, canAct, onChange }: { serverId: string; canAct: boolean; onChange: () => void }) {
  const res = useAgent<{ paused: Paused[] | null; limit: number }>(serverId, 'scanner.paused', {}, 60_000);
  const [bulk, setBulk] = useState<{ sig: string; action: 'restore' | 'quarantine' } | null>(null);
  const { run, busy } = useAction();
  const list = res.data?.paused ?? [];
  if (!list.length) return null;
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 p-4">
      <div className="flex items-center gap-2 font-medium text-red-800">
        <AlertTriangle className="h-5 w-5" /> Paused signatures
      </div>
      <p className="mt-1 text-sm text-red-700">
        These quarantined more than {res.data?.limit} files within an hour, more likely a wrong signature than a real outbreak. Their new detections wait
        here (nothing moved). Check a few, then quarantine them or restore what was quarantined.
      </p>
      <div className="mt-3 space-y-2">
        {list.map((p) => (
          <div key={p.signature} className="flex flex-wrap items-center gap-2 rounded-lg bg-white px-3 py-2 text-sm">
            <span className="font-mono">{p.signature}</span>
            <span className="text-slate-500">
              paused {fmtTime(p.at)} · {p.files.toLocaleString()} waiting
            </span>
            {canAct && (
              <span className="ml-auto flex flex-wrap gap-2">
                <button className="btn-outline px-3 py-1 text-xs" disabled={busy} onClick={() => setBulk({ sig: p.signature, action: 'restore' })}>
                  Restore quarantined…
                </button>
                <button className="btn-outline px-3 py-1 text-xs" disabled={busy} onClick={() => setBulk({ sig: p.signature, action: 'quarantine' })}>
                  Quarantine waiting…
                </button>
                <button
                  className="btn-outline px-3 py-1 text-xs"
                  disabled={busy}
                  onClick={() => run(() => agentCall(serverId, 'scanner.unpause', { signature: p.signature }), 'Unpaused').then(() => (res.reload(), onChange()))}
                >
                  Unpause
                </button>
              </span>
            )}
          </div>
        ))}
      </div>
      {bulk && (
        <BulkFindings
          serverId={serverId}
          signature={bulk.sig}
          action={bulk.action}
          onClose={() => setBulk(null)}
          onDone={() => (res.reload(), onChange())}
        />
      )}
    </div>
  );
}
