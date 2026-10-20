import { describe, expect, it } from 'vitest';
import { csvCell, serverRows } from '../src/routes/learning-export.js';

const srv = { id: 'x', hostname: 'server1.example.net', agent_version: '0.21.34', control_panel: 'cpanel' };

describe('xPGuard Learning export', () => {
  it('writes the server, every rule with its count, and examples while the share lasts', () => {
    const events = Array.from({ length: 200 }, (_, i) => ({
      at: 1792300000, ip: `198.51.100.${i}`, method: 'GET', host: `s${i}.example`, uri: '/wp-admin/edit.php?x="a,b"', rule_id: 7700605,
      msg: 'Web shell name', category: 'webshell', action: 'Access denied with code 403', user: '', detail: 'Pattern match',
    }));
    const s = {
      server: { version: '0.21.34', waf_level: 'normal', waf_enabled: true },
      waf_groups: [{ rule_id: 7700605, msg: 'Web shell name', action: 'Access denied', count: 5000, ips: 900, hosts: 300 }],
      waf_events: events,
    };
    const out = serverRows('waf', srv, 12, s, '', 6000);
    const lines = out.trim().split('\n');
    expect(lines[0]).toContain('server,server1.example.net,0.21.34,cpanel,true,normal');
    expect(lines[1]).toMatch(/^group,.*,7700605,Web shell name,Access denied,5000,900,300/);
    expect(lines[2]).toContain('"/wp-admin/edit.php?x=""a,b"""');
    expect(out.length).toBeLessThanOrEqual(6000);
    expect(lines.length).toBeLessThan(202);
  });

  it('marks servers that could not be asked', () => {
    expect(serverRows('detections', srv, 24, null, 'offline: not included', 1000)).toContain('offline: not included');
  });
});

describe('CSV cells', () => {
  it('never start a formula a spreadsheet would run', () => {
    expect(csvCell('=1+1.php')).toBe("'=1+1.php");
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('-2')).toBe("'-2");
    expect(csvCell('@x')).toBe("'@x");
    expect(csvCell('\t=1+1')).toBe("'\t=1+1");
    expect(csvCell('/=1+1')).toBe('/=1+1');
    expect(csvCell('=1,2')).toBe(`"'=1,2"`);
    expect(csvCell(-5)).toBe('-5');
    expect(csvCell(null)).toBe('');
  });
});
