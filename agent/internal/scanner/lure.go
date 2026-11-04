package scanner

import (
	"bytes"
	"regexp"
)

// The fake "Adobe Acrobat" download kit (server100, aloradecor.com,
// 2026-11-04: reported to Hetzner as a RAT by Outseer). A folder uploaded
// into a WordPress site: a checkbox "I'm not a robot" that only sets a
// session flag, a page sending each visitor's address, ISP and country to
// a Telegram bot, and a page saying the document "requires the latest
// version of Adobe Acrobat" that sends the visitor after ten seconds to
// another site's download.php, a one-line redirect to a ScreenConnect
// access client (remote control of the victim's computer). None of it had
// a finding. xPGuard's own rules, from how each part works:
//
//   - a redirect to a remote-access tool's installer for an unattended
//     session (ScreenConnect/ConnectWise "ClientSetup", AnyDesk, …);
//   - a page that makes the visitor download "the latest version" of a
//     well-known program from another site, automatically;
//   - a script whose only job is to send the visitor's address to a
//     Telegram bot and then send the visitor on;
//   - a "captcha" that is a single checkbox: ticking it is the check.

var (
	// The installer of a remote-access tool, as a link or redirect target.
	// ScreenConnect's access client is ScreenConnect.ClientSetup.exe/.msi
	// (e=Access: an unattended session the attacker keeps).
	reRATInstaller = regexp.MustCompile(`(?i)https?://[a-z0-9.-]+/[^\s"'<>]{0,80}?(?:screenconnect\.clientsetup\.(?:exe|msi)|connectwisecontrol\.clientsetup\.(?:exe|msi)|/bin/[a-z0-9._-]*clientsetup\.(?:exe|msi))[^\s"'<>]{0,200}`)
	// How a page sends the browser there by itself (a link a visitor
	// clicks is not this: IT support companies link their support client).
	reRedirectTo = regexp.MustCompile(`(?i)header\s*\(\s*['"]\s*location\s*:\s*['"]?|http-equiv\s*=\s*["']?refresh|(?:window|document|top|self)\.location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(`)
	// An unattended-access session (the attacker keeps the computer), not
	// a support session someone joins.
	reAccessSession = regexp.MustCompile(`(?i)[?&]e=access\b`)

	// "requires the latest version of Adobe Acrobat", "update your Zoom"…
	reUpdateLure = regexp.MustCompile(`(?i)(?:requires?|need(?:s|ed)?|install|download|update)\b[^<]{0,60}\b(?:latest|newest|new|updated|current)\s+version\s+of\s+(?:adobe|acrobat|pdf|zoom|microsoft|ms\s|teams|office|outlook|word|excel|onedrive|chrome|google|java|flash|docusign|skype|whatsapp|telegram)`)
	// …and it downloads by itself, from another address.
	reAutoDownload = regexp.MustCompile(`(?i)http-equiv\s*=\s*["']?refresh["']?\s+content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*https?://|(?:window|document)\.location(?:\.href)?\s*=\s*["']https?://|will\s+download\s+automatically`)

	// A visitor's details sent to a Telegram bot.
	reTGSend      = regexp.MustCompile(`(?i)api\.telegram\.org/bot`)
	reVisitorInfo = regexp.MustCompile(`(?i)\bREMOTE_ADDR\b|HTTP_X_FORWARDED_FOR|HTTP_CF_CONNECTING_IP`)
	reGeoLookup   = regexp.MustCompile(`(?i)ip-api\.com|ipinfo\.io|ipapi\.co|geoplugin|ipwho\.is|ip-api\.io|freegeoip|\bgethostbyaddr\s*\(`)
	reSendsOn     = regexp.MustCompile(`(?i)header\s*\(\s*['"]\s*location\s*:`)
	// A form's own fields read (a contact or order form sends those).
	reFormFields = regexp.MustCompile(`\$_(?:POST|GET|REQUEST)\s*\[`)

	// The checkbox "captcha": the box's value alone sets the session flag.
	reBoxCaptcha = regexp.MustCompile(`(?is)\$_POST\s*\[\s*['"](\w*(?:captcha|robot|human|verify)\w*)['"]\s*\]\s*\)?\s*(?:&&\s*\$_POST\s*\[\s*['"]\w+['"]\s*\]\s*===?\s*['"]on['"])?[^;{]{0,80}\{?\s*\$_SESSION\s*\[\s*['"]\w*(?:captcha|verified|human)\w*['"]\s*\]\s*=\s*(?:true|1|['"]1['"])`)
	reBoxInput   = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?checkbox[^>]*>[^<]{0,40}(?:i'?m|i am)\s+not\s+a\s+robot`)
)

// downloadLure judges pages of the fake-download kits (analyze).
func downloadLure(ext string, content []byte) *Detection {
	if ext != ".php" && ext != ".html" && ext != ".htm" && ext != ".phtml" {
		return nil
	}
	low := bytes.ToLower(content)
	// Sent there by itself: from a file that does nothing else (download.php,
	// one header() line), or into an unattended-access session.
	if bytes.Contains(low, []byte("clientsetup.")) && reRATInstaller.Match(content) && reRedirectTo.Match(content) &&
		(len(content) < 4096 || reAccessSession.Match(content)) {
		return &Detection{CatVirus, "Malware.Redirect.RemoteAccessInstaller"}
	}
	if bytes.Contains(low, []byte("version of")) && reUpdateLure.Match(content) && reAutoDownload.Match(content) {
		return &Detection{CatVirus, "Phishing.FakeUpdate.DownloadLure"}
	}
	if ext != ".html" && ext != ".htm" && bytes.Contains(low, []byte("api.telegram.org")) && reTGSend.Match(content) &&
		reVisitorInfo.Match(content) && reGeoLookup.Match(content) && reSendsOn.Match(content) && !reFormFields.Match(content) {
		return &Detection{CatVirus, "Phishing.Collector.TelegramVisitLogger"}
	}
	if bytes.Contains(low, []byte("not a robot")) && reBoxInput.Match(content) && reBoxCaptcha.Match(content) {
		return &Detection{CatVirus, "Phishing.FakeCaptcha.CheckboxGate"}
	}
	return nil
}
