import { History, RotateCcw } from 'lucide-react';
import { Empty, ErrorBox, SectionLoader } from './ui';
import { agentCall, fmtTime, useAction, useAgent } from './controls';

interface Entry {
  id: number;
  at: number;
  summary: string;
}

/** Settings » History: every change on this server, each one undoable. */
export function SettingsHistory({ serverId, admin, onRolledBack }: { serverId: string; admin: boolean; onRolledBack: () => void }) {
  const res = useAgent<{ history: Entry[] | null }>(serverId, 'settings.history');
  const { run, busy } = useAction();
  const list = res.data?.history ?? [];
  return (
    <div>
      <h2 className="flex items-center gap-2 text-lg font-semibold text-navy-900">
        <History className="h-5 w-5" /> Settings history
      </h2>
      <p className="mb-4 text-sm text-slate-500">
        Each change on this server, newest first. "Undo" puts back the settings as they were just before that change (later changes are undone too); an undo
        can itself be undone. For every server at once use Fleet health » Roll back.
      </p>
      {res.error && <ErrorBox message={res.error.includes('unsupported') ? 'Update the agent to keep a settings history.' : res.error} />}
      {res.loading && !res.data ? (
        <SectionLoader />
      ) : list.length === 0 ? (
        <Empty text="No settings changes recorded yet." />
      ) : (
        <div className="divide-y divide-slate-100 rounded-lg border border-slate-200">
          {list.map((e) => (
            <div key={e.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
              <span className="w-44 shrink-0 text-slate-500">{fmtTime(e.at)}</span>
              <span className="min-w-0 flex-1 font-mono text-xs break-all text-slate-700">{e.summary}</span>
              {admin && (
                <button
                  className="btn-outline px-3 py-1 text-xs"
                  disabled={busy}
                  onClick={async () => {
                    if (!confirm(`Put back the settings from before ${fmtTime(e.at)}? Changes made since then are undone too.`)) return;
                    const r = await run(() => agentCall(serverId, 'settings.rollback', { id: e.id }), 'Settings rolled back');
                    if (r) {
                      res.reload();
                      onRolledBack();
                    }
                  }}
                >
                  <RotateCcw className="h-3.5 w-3.5" /> Undo
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
