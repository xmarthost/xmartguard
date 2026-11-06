package scanner

import (
	"bytes"
	"regexp"
)

// Phishing kits on shared hosting come in two parts: a copy of a bank or
// payment login page, and a PHP "collector" that receives the form and
// sends the victim's details to the attacker (mail or a Telegram bot).
// These checks are xPGuard's own, built from how such kits work.

var (
	rePhishExfil = regexp.MustCompile(`(?i)api\.telegram\.org/bot|\bmail\s*\(\s*\$\w+\s*,`)
	// Card and bank details: what a collector asks for and a site's own
	// login or registration controller does not.
	rePhishBankField = regexp.MustCompile(`(?i)\$_(?:POST|REQUEST)\s*\[\s*['"](?:[\w-]*(?:ssn|cvv|cvc|ccnum|cardnum|card_?number|cc_?num|exp(?:iry|date)|routing|acc(?:ount)?_?num|mmn|atm))['"]`)
	rePhishTelegram  = regexp.MustCompile(`(?i)api\.telegram\.org/bot`)
	rePhishFields    = regexp.MustCompile(`(?i)\$_(?:POST|REQUEST)\s*\[\s*['"](?:[\w-]*(?:ssn|cvv|cvc|ccnum|cardnum|card_?number|cc_?num|exp(?:iry|date)|otp|pin|routing|acc(?:ount)?_?num|pass(?:word|wd)?|mmn|dob|atm))['"]`)
	rePhishVisitor   = regexp.MustCompile(`(?i)REMOTE_ADDR|HTTP_USER_AGENT|HTTP_X_FORWARDED_FOR`)

	rePhishBrand    = regexp.MustCompile(`(?i)<title>[^<]{0,120}\b(?:chase|wells\s*fargo|bank\s*of\s*america|navy\s*federal|citizens\s*bank|capital\s*one|usaa|paypal|td\s*bank|pnc\s*bank|regions\s*bank|huntington|truist|us\s*bank|santander|barclays|hsbc|lloyds|halifax|natwest|amex|american\s*express|netflix|microsoft\s*(?:365|outlook|account)|office\s*365|apple\s*id|icloud|coinbase|binance|metamask)\b`)
	rePhishPassword = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*['"]?password`)
	rePhishCard     = regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*['"]?[\w-]*(?:ssn|cvv|cvc|ccnum|cardnum|card_?number|routing|otp)`)
	// A password field, in HTML or made by script.
	rePhishPasswordAny = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*['"]?password|\.type\s*=\s*['"]password['"]|getElementById\(\s*['"][\w-]*pass(?:word|wd)?[\w-]*['"]\s*\)\.value`)
	// Sent from the browser (fetch, XMLHttpRequest, jQuery, a form post).
	rePhishClientSend = regexp.MustCompile(`(?i)\bfetch\s*\(|XMLHttpRequest|\$\.(?:ajax|post|get)\s*\(|navigator\.sendBeacon|<form[^>]+action\s*=\s*['"]?https?://api\.telegram\.org`)
	rePhishAction     = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*['"]?[^'" >]*\.php`)
)

// phishMay rules out most files before the collector regexps run.
func phishMay(content []byte) bool {
	low := lowerASCII(content)
	return may(rePhishVisitor, low) && may(rePhishExfil, low)
}

// phishingKit reports a phishing collector script (virus) or a cloned
// bank/payment login page (suspicious).
func phishingKit(ext string, content []byte) *Detection {
	switch ext {
	case ".php", ".phtml", ".inc", ".html", ".htm", "":
	default:
		return nil
	}
	if bytes.Contains(content, []byte("<?")) && phishMay(content) && rePhishExfil.Match(content) && rePhishVisitor.Match(content) {
		// Collectors ask for several secrets at once; a contact form never
		// does. An application's own user controller asks for a password,
		// a PIN or an OTP and mails the user too, so without a Telegram bot
		// card or bank fields are needed.
		if n := len(rePhishFields.FindAll(content, 8)); n >= 3 && (rePhishTelegram.Match(content) || len(rePhishBankField.FindAll(content, 3)) >= 2) {
			return &Detection{CatVirus, "Phishing.Collector"}
		}
	}
	// A login page that sends what is typed to a Telegram bot from the
	// browser (glasgowfitness.com on business200, 2026-11-06: a Microsoft
	// sign-in copy at wp-content/maintenance/assets/HOT2.htm, beside WP
	// Toolkit's own maintenance page; it took the address and two
	// passwords, added the visitor's IP and posted them to the bot). No
	// form, no PHP: the clone rule did not see it. A site never puts a
	// bot's token and a password field in a page.
	if (ext == ".html" || ext == ".htm" || ext == ".php" || ext == ".phtml") && bytes.Contains(lowerASCII(content), []byte("api.telegram.org/bot")) &&
		rePhishTelegram.Match(content) && rePhishPasswordAny.Match(content) && rePhishClientSend.Match(content) {
		return &Detection{CatVirus, "Phishing.Credentials.TelegramExfil"}
	}
	if (ext == ".html" || ext == ".htm" || ext == ".php") && rePhishBrand.Match(content) &&
		(rePhishPassword.Match(content) || rePhishCard.Match(content)) && rePhishAction.Match(content) {
		return &Detection{CatSuspicious, "Phishing.CloneLoginPage"}
	}
	return nil
}
