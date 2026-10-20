/** Input checks shared by every page (Allow list, rule exclusions, IP lists). */

/** A domain like example.com or *.example.com (labels do not start or end with "-"; not an IP). */
export function isDomain(v: string): boolean {
  return /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(v) && !/^(?:\*\.)?[\d.]+$/.test(v);
}

/** null if v is an IPv4/IPv6 address or CIDR range, else an error message. */
export function isIPorCIDR(v: string): string | null {
  const bad = `${v} is not a valid IP address or CIDR`;
  const [addr, prefix, ...rest] = v.split('/');
  if (rest.length || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) return bad;
  const ip4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (ip4) return ip4.slice(1).every((o) => Number(o) <= 255) && (prefix === undefined || Number(prefix) <= 32) ? null : bad;
  if (!addr.includes(':') || !/^[0-9a-fA-F:]+$/.test(addr) || (prefix !== undefined && Number(prefix) > 128)) return bad;
  const groups = addr.split('::');
  if (groups.length > 2) return bad;
  const parts = groups.flatMap((g) => (g ? g.split(':') : []));
  if (parts.some((p) => !/^[0-9a-fA-F]{1,4}$/.test(p))) return bad;
  return (groups.length === 2 ? parts.length < 8 : parts.length === 8) ? null : bad;
}
