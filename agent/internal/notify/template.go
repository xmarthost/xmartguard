package notify

import (
	"bytes"
	"html/template"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Email is one notification message: the alerts batched for a recipient.
type Email struct {
	Subject string
	Host    string
	Alerts  []Alert
	// ForAdmin: the server administrator (links to the portal); otherwise
	// a hosting account owner.
	ForAdmin  bool
	PortalURL string
}

// Row is a "label: value" line of an alert.
type Row struct{ Key, Value string }

// Item is an alert laid out for the template.
type Item struct {
	Kind  string // subject of the alert
	Title string
	Rows  []Row
	Notes []string
}

var reRow = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 /()_.-]{0,38}?)\s*:\s+(\S.*)$`)

// items turns the plain-text alerts into titles, label/value rows and notes.
func (e Email) items() []Item {
	var out []Item
	for _, a := range e.Alerts {
		it := Item{Kind: a.Subject}
		for _, l := range strings.Split(strings.TrimRight(a.Text, "\n"), "\n") {
			t := strings.TrimSpace(l)
			if t == "" {
				continue
			}
			if it.Title == "" && !reRow.MatchString(l) {
				it.Title = t
				continue
			}
			if m := reRow.FindStringSubmatch(l); m != nil && !strings.Contains(m[1], "http") {
				it.Rows = append(it.Rows, Row{strings.TrimSpace(m[1]), m[2]})
				continue
			}
			it.Notes = append(it.Notes, t)
		}
		if it.Title == "" {
			it.Title = a.Subject
		}
		out = append(out, it)
	}
	return out
}

// tone picks the banner colour and label from what the alerts are about.
func (e Email) tone() (color, bg, label string) {
	s := strings.ToLower(e.Subject)
	for _, a := range e.Alerts {
		s += " " + strings.ToLower(a.Subject)
	}
	switch {
	case strings.Contains(s, "test notification"):
		return "#15803d", "#dcfce7", "Test message"
	case strings.Contains(s, "report"):
		return "#1d4ed8", "#dbeafe", "Security report"
	case strings.Contains(s, "malware") || strings.Contains(s, "infect") || strings.Contains(s, "cron") ||
		strings.Contains(s, "process") || strings.Contains(s, "rootkit") || strings.Contains(s, "spam") || strings.Contains(s, "injected"):
		return "#b91c1c", "#fee2e2", "Threat detected"
	case strings.Contains(s, "blacklist") || strings.Contains(s, "suspend") || strings.Contains(s, "blocked"):
		return "#b45309", "#fef3c7", "Action taken"
	case strings.Contains(s, "restored") || strings.Contains(s, "repaired") || strings.Contains(s, "patch") || strings.Contains(s, "outdated"):
		return "#1d4ed8", "#dbeafe", "Maintenance"
	}
	return "#1d4ed8", "#dbeafe", "Notice"
}

func (e Email) headline() string {
	if len(e.Alerts) == 0 {
		return e.Subject
	}
	h := e.Alerts[0].Subject
	if h != "" {
		h = strings.ToUpper(h[:1]) + h[1:]
	}
	if len(e.Alerts) > 1 {
		return h + " and " + plural(len(e.Alerts)-1, "more alert")
	}
	return h
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return strconv.Itoa(n) + " " + w + "s"
}

// Now is the clock shown in emails (tests override it).
var Now = time.Now

// Text is the plain-text part.
func (e Email) Text() string {
	var b strings.Builder
	_, _, label := e.tone()
	b.WriteString("xPGuard · " + label + " · " + e.Host + "\n")
	b.WriteString(strings.Repeat("=", 48) + "\n\n")
	for i, a := range e.Alerts {
		if i > 0 {
			b.WriteString("\n" + strings.Repeat("-", 48) + "\n")
		}
		if len(e.Alerts) > 1 {
			b.WriteString(strings.ToUpper(a.Subject) + "\n")
		}
		b.WriteString(strings.TrimRight(a.Text, "\n") + "\n")
	}
	b.WriteString("\n" + strings.Repeat("-", 48) + "\n")
	b.WriteString("Sent by xPGuard on " + e.Host + " at " + Now().Format("2 Jan 2006 15:04 MST") + ".\n")
	if e.ForAdmin && e.PortalURL != "" {
		b.WriteString("Open the portal: " + e.PortalURL + "\n")
		b.WriteString("Change these alerts in Settings » Notifications.\n")
	} else if !e.ForAdmin {
		b.WriteString("You receive this because you own a hosting account on this server. Contact your hosting provider for help.\n")
	}
	return b.String()
}

// HTML is the HTML part: a 600px table layout with inline styles (the only
// styling every mail client honours), stacked on phones.
func (e Email) HTML() (string, error) {
	color, bg, label := e.tone()
	data := map[string]any{
		"Subject":   e.Subject,
		"Headline":  e.headline(),
		"Host":      e.Host,
		"Label":     label,
		"Color":     color,
		"Bg":        bg,
		"Items":     e.items(),
		"Many":      len(e.Alerts) > 1,
		"Count":     len(e.Alerts),
		"ForAdmin":  e.ForAdmin,
		"PortalURL": e.PortalURL,
		"Time":      Now().Format("2 Jan 2006, 15:04 MST"),
		"Year":      Now().Year(),
		"LogoCID":   template.URL("cid:" + logoCID),
	}
	var b bytes.Buffer
	if err := emailTmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

var emailTmpl = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>{{.Subject}}</title>
<style>
  body { margin:0; padding:0; background:#eef2f7; }
  a { color:#1d4ed8; }
  @media only screen and (max-width:620px) {
    .wrap { width:100% !important; }
    .px { padding-left:20px !important; padding-right:20px !important; }
    .kv td { display:block !important; width:100% !important; padding:2px 0 !important; }
    .kv td.k { padding-top:8px !important; }
    .h1 { font-size:20px !important; }
    .btn a { display:block !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#eef2f7;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{{.Label}} on {{.Host}}: {{.Headline}}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eef2f7;">
<tr><td align="center" style="padding:24px 12px;">
  <table role="presentation" class="wrap" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #dbe3ee;">
    <tr><td style="height:5px;line-height:5px;font-size:0;background:#f97316;background-image:linear-gradient(90deg,#f97316,#2563eb);">&nbsp;</td></tr>
    <tr><td class="px" style="padding:22px 32px 18px;border-bottom:1px solid #eef2f7;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td align="left" valign="middle"><img src="{{.LogoCID}}" width="170" height="31" alt="xPGuard" style="display:block;border:0;outline:none;width:170px;height:auto;"></td>
        <td align="right" valign="middle" style="font:12px/1.4 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#64748b;">Proactive server security</td>
      </tr></table>
    </td></tr>
    <tr><td class="px" style="padding:26px 32px 6px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      <span style="display:inline-block;padding:4px 12px;border-radius:999px;background:{{.Bg}};color:{{.Color}};font-size:12px;font-weight:700;letter-spacing:.3px;text-transform:uppercase;">{{.Label}}</span>
      <h1 class="h1" style="margin:14px 0 6px;font-size:22px;line-height:1.3;color:#0f172a;font-weight:700;">{{.Headline}}</h1>
      <p style="margin:0;font-size:14px;line-height:1.5;color:#475569;">Server <b style="color:#0f172a;">{{.Host}}</b> &middot; {{.Time}}</p>
    </td></tr>
    <tr><td class="px" style="padding:18px 32px 8px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      {{range .Items}}
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 14px;border:1px solid #e2e8f0;border-left:4px solid {{$.Color}};border-radius:10px;background:#f8fafc;">
        <tr><td style="padding:14px 16px;">
          {{if $.Many}}<div style="font-size:11px;font-weight:700;color:{{$.Color}};text-transform:uppercase;letter-spacing:.4px;margin:0 0 4px;">{{.Kind}}</div>{{end}}
          <div style="font-size:15px;line-height:1.45;font-weight:600;color:#0f172a;word-break:break-word;">{{.Title}}</div>
          {{if .Rows}}
          <table role="presentation" class="kv" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:8px;">
            {{range .Rows}}<tr>
              <td class="k" valign="top" width="130" style="padding:5px 12px 5px 0;font-size:12px;line-height:1.5;color:#64748b;text-transform:capitalize;white-space:nowrap;">{{.Key}}</td>
              <td valign="top" style="padding:5px 0;font-size:13px;line-height:1.5;color:#0f172a;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all;">{{.Value}}</td>
            </tr>{{end}}
          </table>
          {{end}}
          {{range .Notes}}<p style="margin:8px 0 0;font-size:13px;line-height:1.5;color:#334155;word-break:break-word;">{{.}}</p>{{end}}
        </td></tr>
      </table>
      {{end}}
    </td></tr>
    {{if and .ForAdmin .PortalURL}}
    <tr><td class="px btn" align="left" style="padding:6px 32px 26px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      <a href="{{.PortalURL}}" style="display:inline-block;padding:12px 22px;border-radius:10px;background:#1e3a8a;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;text-align:center;">Open xPGuard portal &rarr;</a>
    </td></tr>
    {{end}}
    <tr><td class="px" style="padding:18px 32px 22px;background:#0f172a;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
      <p style="margin:0 0 6px;font-size:13px;line-height:1.5;color:#e2e8f0;font-weight:600;">xPGuard &middot; <span style="color:#fb923c;">Proactive server security</span></p>
      {{if .ForAdmin}}
      <p style="margin:0;font-size:12px;line-height:1.6;color:#94a3b8;">Sent automatically by the xPGuard agent on {{.Host}}. Choose which alerts you receive in {{if .PortalURL}}<a href="{{.PortalURL}}" style="color:#93c5fd;">the portal</a>{{else}}the portal{{end}} &raquo; Settings &raquo; Notifications.</p>
      {{else}}
      <p style="margin:0;font-size:12px;line-height:1.6;color:#94a3b8;">You receive this because you own a hosting account on {{.Host}}. For help, contact your hosting provider.</p>
      {{end}}
      <p style="margin:8px 0 0;font-size:11px;line-height:1.5;color:#64748b;">&copy; {{.Year}} xPGuard. This is an automated message; please do not reply.</p>
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>
`))
