import { useState } from 'react';
import { Tag } from 'lucide-react';
import { api, type Server } from '../api';
import ModernServerList from './ServerListModern';

export function TagEditor({ server, onSaved }: { server: Server; onSaved: () => void }) {
  const [value, setValue] = useState(server.tags.join(', '));
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <button
        className="btn-outline px-3 py-1.5 text-sm"
        onClick={() => setOpen(true)}
      >
        <Tag className="h-4 w-4" /> {server.tags.length ? 'Edit Tags' : 'Assign Tag'}
      </button>
    );
  }
  return (
    <form
      className="flex gap-1"
      onSubmit={async (e) => {
        e.preventDefault();
        const tags = value.split(',').map((t) => t.trim()).filter(Boolean);
        await api('PATCH', `/api/servers/${server.id}`, { tags });
        setOpen(false);
        onSaved();
      }}
    >
      <input className="input py-1 text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder="tag1, tag2" autoFocus />
      <button className="btn-primary px-2 py-1 text-xs">Save</button>
    </form>
  );
}

export default function ServerList() {
  return <ModernServerList />;
}
