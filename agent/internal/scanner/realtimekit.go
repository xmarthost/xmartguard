package scanner

import (
	"bytes"
	"regexp"
	"strings"
)

// The Mercantil kit of mangomela.com.au (2026-11-06, Google Safe Browsing
// listed the site): a fake "wp-merc" folder with a bank login copy, a
// loader page that asks the attacker's panel what to show next (SMS code,
// card security code, security questions) and sends the victim there, and
// next to it droppers that download and start a program and a loader that
// evals a payload spelled in 200,000 pieces. None of it had a finding.
// xPGuard's own rules, from how each part works.

var (
	// A program downloaded, made executable and started in one command.
	reDownloadRun = regexp.MustCompile(`(?is)\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(.{0,400}?\b(?:wget|curl)\b.{0,400}?\bchmod\s+(?:\+x|[0-7]{3,4}|[ugoa]*\+x)\b.{0,300}?(?:\bnohup\b|&&\s*["'.\s]*\$|&&\s*\./)`)

	// A waiting page that polls the panel and sends the victim to the next
	// step it names.
	rePoll     = regexp.MustCompile(`(?i)\bsetInterval\s*\(|\bsetTimeout\s*\(`)
	reAskPanel = regexp.MustCompile("(?i)\\bfetch\\s*\\(|XMLHttpRequest|\\$\\.(?:ajax|get|post|getJSON)\\s*\\(")
	reStepPage = regexp.MustCompile("(?i)location(?:\\.href)?\\s*=\\s*['\"`][^'\"`]{0,60}?\\b(sms|otp|cvv|cvc|token|pin|preguntas|questions|tarjeta|card|clave|codigo|code|dinamica)[\\w-]*\\.(?:html?|php)")
	// A page that sends a card's security code to the panel as a step.
	reCardStep = regexp.MustCompile("(?i)(?:\\bfetch\\s*\\(|\\$\\.(?:ajax|post)\\s*\\(|\\.open\\s*\\(\\s*['\"]post['\"])[^;]{0,120}?[?&](?:(?:accion|action|step|paso|etapa)=(?:cvv|cvc)|accion=tarjeta)\\b")
)

// realtimeKit judges the pages of operator-driven phishing kits.
func realtimeKit(ext string, content []byte) *Detection {
	if ext != ".html" && ext != ".htm" && ext != ".php" && ext != ".phtml" {
		return nil
	}
	low := bytes.ToLower(content)
	if reCardStep.Match(content) {
		return &Detection{CatVirus, "Phishing.Kit.CardStep"}
	}
	if bytes.Contains(low, []byte("location")) && rePoll.Match(content) && reAskPanel.Match(content) {
		steps := map[string]bool{}
		for _, m := range reStepPage.FindAllSubmatch(content, 20) {
			steps[strings.ToLower(string(m[1]))] = true
		}
		if len(steps) >= 2 {
			return &Detection{CatVirus, "Phishing.Kit.OperatorLoader"}
		}
	}
	return nil
}

// hiddenDecoder: a decoder's name spelled in pieces or escapes
// ($fn = 'base'.'64_decode') in a file that evals.
var hiddenDecoders = map[string]bool{"base64_decode": true, "gzinflate": true, "gzuncompress": true, "gzdecode": true,
	"str_rot13": true, "hex2bin": true, "convert_uudecode": true, "bzdecompress": true}

func hiddenDecoder(s []byte) bool {
	for _, n := range disguisedNames(s) {
		if hiddenDecoders[n] {
			return true
		}
	}
	return false
}
