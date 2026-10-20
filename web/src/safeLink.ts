/**
 * Links sent by an agent (dashboard alerts, protection chips, the header
 * bell) are pages of that server: "scanner-logs", "scanner-logs?paused=1".
 * The agent runs on the customer's server, so its answer is not trusted:
 * anything else (an absolute URL, "//host", "../") becomes '' and is not
 * shown as a link, so a changed agent cannot send the master to another site.
 */
export function serverPageLink(link: unknown): string {
  return typeof link === 'string' && /^[a-z0-9-]+(?:\?[A-Za-z0-9=&_-]*)?$/.test(link) ? link : '';
}
