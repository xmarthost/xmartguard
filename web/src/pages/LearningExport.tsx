import { useState, type ReactNode } from 'react';
import { Download, FileSearch, ShieldCheck } from 'lucide-react';

const HOURS = [1, 6, 12, 24, 48, 72, 168];

/**
 * Master: exports for reviewing how the WAF and the scanner behave on every
 * server. Nothing here changes a server: the files are read, reviewed, and
 * improvements are released as updates.
 */
/** A tab of LearningCenter (its old route redirects there). */
export default function LearningExport() {
  const [hours, setHours] = useState(24);
  const card = (kind: 'waf' | 'detections', icon: ReactNode, title: string, desc: string, cols: string) => (
    <div className="card flex flex-col gap-3 p-5">
      <div className="flex items-center gap-2 font-medium text-navy-900">
        {icon} {title}
      </div>
      <p className="text-sm text-slate-500">{desc}</p>
      <p className="text-xs text-slate-400">Columns: {cols}</p>
      <div>
        <a className="btn-primary" href={`/api/learning/export?kind=${kind}&hours=${hours}`}>
          <Download className="h-4 w-4" /> Download ({hours >= 24 ? `${hours / 24} day${hours > 24 ? 's' : ''}` : `${hours} h`})
        </a>
      </div>
    </div>
  );
  return (
    <div className="space-y-5">
      <div className="max-w-3xl">
        <h1 className="h-title">xPGuard Learning</h1>
        <p className="text-sm text-slate-500">
          Review files from every server. Each file is a CSV of at most 25 MB that the servers share equally: for each server its settings, every WAF
          rule (or detection signature) with how often it fired in the time window, and a few examples of each from different websites and files, so one
          busy server or one noisy rule cannot fill the file. Nothing is learned or changed automatically: send these files for review and fixes are
          released as updates. Offline servers and servers with an older agent are listed with a note.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-slate-600">Time window:</span>
        {HOURS.map((h) => (
          <button key={h} className={hours === h ? 'btn-primary' : 'btn-outline'} onClick={() => setHours(h)}>
            {h >= 24 ? `${h / 24} day${h > 24 ? 's' : ''}` : `${h} h`}
          </button>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {card(
          'waf',
          <ShieldCheck className="h-5 w-5" />,
          'WAF logs',
          'Requests the WAF blocked or counted: rule, website, address, request and what matched, with the WAF settings of each server.',
          'row_type (server / group / example), server, version, WAF level, rule id and message, rule total, addresses and sites, time, method, host, URI, IP, matched',
        )}
        {card(
          'detections',
          <FileSearch className="h-5 w-5" />,
          'Scanner detections',
          'Files the scanner flagged: signature, path, status (quarantined, restored by the AI…), the AI’s verdict and reason, and the matched lines of pattern rules.',
          'row_type (server / group / example), server, version, scanner actions, signature, category, status, totals, path, owner, size, SHA-256, AI verdict, matched code',
        )}
      </div>
      <p className="text-xs text-slate-400">Preparing a file asks every server and can take up to a minute and a half.</p>
    </div>
  );
}
