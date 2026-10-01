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
	rePhishExfil   = regexp.MustCompile(`(?i)api\.telegram\.org/bot|\bmail\s*\(\s*\$\w+\s*,`)
	rePhishFields  = regexp.MustCompile(`(?i)\$_(?:POST|REQUEST)\s*\[\s*['"](?:[\w-]*(?:ssn|cvv|cvc|ccnum|cardnum|card_?number|cc_?num|exp(?:iry|date)|otp|pin|routing|acc(?:ount)?_?num|pass(?:word|wd)?|mmn|dob|atm))['"]`)
	rePhishVisitor = regexp.MustCompile(`(?i)REMOTE_ADDR|HTTP_USER_AGENT|HTTP_X_FORWARDED_FOR`)

	rePhishBrand    = regexp.MustCompile(`(?i)<title>[^<]{0,120}\b(?:chase|wells\s*fargo|bank\s*of\s*america|navy\s*federal|citizens\s*bank|capital\s*one|usaa|paypal|td\s*bank|pnc\s*bank|regions\s*bank|huntington|truist|us\s*bank|santander|barclays|hsbc|lloyds|halifax|natwest|amex|american\s*express|netflix|microsoft\s*(?:365|outlook)|office\s*365|apple\s*id|icloud|coinbase|binance|metamask)\b`)
	rePhishPassword = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*['"]?password`)
	rePhishCard     = regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*['"]?[\w-]*(?:ssn|cvv|cvc|ccnum|cardnum|card_?number|routing|otp)`)
	rePhishAction   = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*['"]?[^'" >]*\.php`)
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
		// Collectors ask for several secrets at once; a contact form never does.
		if n := len(rePhishFields.FindAll(content, 8)); n >= 3 {
			return &Detection{CatVirus, "Phishing.Collector"}
		}
	}
	if (ext == ".html" || ext == ".htm" || ext == ".php") && rePhishBrand.Match(content) &&
		(rePhishPassword.Match(content) || rePhishCard.Match(content)) && rePhishAction.Match(content) {
		return &Detection{CatSuspicious, "Phishing.CloneLoginPage"}
	}
	return nil
}
