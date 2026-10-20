package firewall

import "testing"

// parseAny runs every rule of a service over a line, like RunBruteForce.
func parseAny(service, line string) (string, bool) {
	for _, r := range LogRules {
		if r.Service == service {
			if ip, ok := r.ParseLine(line); ok {
				return ip, true
			}
		}
	}
	return "", false
}

// Text the client chooses (user name, HELO, sender, SMTP command, URL,
// disconnect message) must never put another address where the client's
// is read: 192.0.2.66 is the client, 198.51.100.99 the address it names.
// Each line yields the client or nothing.
func TestLogRulesIgnoreInjectedAddress(t *testing.T) {
	const client, victim = "192.0.2.66", "198.51.100.99"
	cases := []struct{ service, line string }{
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Invalid user x from 198.51.100.99 from 192.0.2.66 port 4000"},
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Failed password for invalid user x from 198.51.100.99 port 1 ssh2 from 192.0.2.66 port 4000 ssh2"},
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Disconnected from invalid user x 198.51.100.99 port 1 [preauth] 192.0.2.66 port 4000 [preauth]"},
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Connection closed by authenticating user x 198.51.100.99 192.0.2.66 port 4000 [preauth]"},
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Received disconnect from 192.0.2.66 port 4000:11: sshd[2]: Invalid user x from 198.51.100.99 port 1 [preauth]"},
		{"Mail (Exim SMTP auth)", "2026-09-26 10:00:00 dovecot_login authenticator failed for ([198.51.100.99]) [192.0.2.66]:4000: 535 Incorrect authentication data (set_id=a[198.51.100.99])"},
		{"Mail (Exim abuse)", "2026-09-26 10:00:00 H=([198.51.100.99]) [192.0.2.66]:4000 F=<a[198.51.100.99]@example.com> rejected RCPT <x@example.org>: relay not permitted"},
		{"Mail (Exim abuse)", `2026-09-26 10:00:00 SMTP call from (x) [192.0.2.66]:4000 dropped: too many nonmail commands (last was "SMTP call from [198.51.100.99] dropped: too many nonmail commands")`},
		{"Mail (Exim abuse)", `2026-09-26 10:00:00 SMTP protocol synchronization error (next input sent too soon: pipelining was not advertised): rejected "EHLO a" H=[198.51.100.99]:1 next input="" H=[192.0.2.66]:4000 next input="x"`},
		{"Mail (Exim abuse)", `2026-09-26 10:00:00 SMTP protocol synchronization error (input sent without waiting for greeting): rejected connection from H=[192.0.2.66]:4000 input="H=[198.51.100.99]"`},
		{"Mail (Dovecot)", "Sep 26 10:00:00 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from x[192.0.2.66]: 554 from=<dovecot: auth failed rip=198.51.100.99>"},
		{"Mail (Postfix SASL)", "Sep 26 10:00:00 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from x[192.0.2.66]: helo=<warning: x[198.51.100.99]: SASL LOGIN authentication failed>"},
		{"FTP", `Sat Sep 26 10:00:00 2026 [pid 1] [x" FAIL LOGIN: Client "198.51.100.99" y] FAIL LOGIN: Client "::ffff:192.0.2.66"`},
		{"FTP", "Sep 26 10:00:00 host proftpd[12]: host.example.com (192.0.2.66[192.0.2.66]) - USER x [198.51.100.99] y: no such user found from 192.0.2.66 [192.0.2.66] to 10.0.0.1:21"},
		{"Web (denied)", "[Sat Sep 26 10:00:00.1 2026] [core:info] [pid 1] [client 192.0.2.66:5555] AH00128: File does not exist: /x [client 198.51.100.99] AH01630"},
		{"cPanel/WHM/Webmail", `[2026-09-26 10:00:00 +0000] info [cpaneld] 192.0.2.66 - FAILED LOGIN cpaneld: x ip=198.51.100.99 "POST /login/ HTTP/1.1" FAILED LOGIN cpaneld: user password incorrect`},
	}
	for _, c := range cases {
		if ip, ok := parseAny(c.service, c.line); ok && ip != client {
			t.Errorf("%s: read %s from %q", c.service, ip, c.line)
		} else if ip == victim {
			t.Errorf("%s: victim read", c.service)
		}
	}
	// Real attacks are still caught, in the forms the anchors must allow.
	real := []struct{ service, line string }{
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Invalid user x from 198.51.100.99 from 192.0.2.66 port 4000"},
		{"SSH", "Sep 26 10:01:02 host sshd[1]: Failed publickey for root from 192.0.2.66 port 4000 ssh2: RSA SHA256:abc"},
		{"SSH", "2026-09-26T10:01:02.123+00:00 host sshd[1]: Disconnected from invalid user a b 192.0.2.66 port 4000 [preauth]"},
		{"Mail (Exim SMTP auth)", "2026-09-26 10:00:00 [1234] dovecot_login authenticator failed for host.example.com (x) [192.0.2.66]:4000: 535 Incorrect authentication data"},
		{"Mail (Exim abuse)", "2026-09-26 10:00:00 SMTP connection from [192.0.2.66]:4000 I=[10.0.0.1]:25 closed by DROP in ACL"},
		{"Mail (Exim abuse)", `2026-09-26 10:00:00 SMTP protocol synchronization error (input sent without waiting for greeting): rejected connection from H=[192.0.2.66]:4000 input="x"`},
		{"FTP", "Sep 26 10:00:00 host proftpd[12]: host.example.com (192.0.2.66[192.0.2.66]) - USER bob: no such user found from 192.0.2.66 [192.0.2.66] to 10.0.0.1:21"},
		{"FTP", "Sep 26 10:00:00 host pure-ftpd[3]: (?@192.0.2.66) [WARNING] Authentication failed for user [bob]"},
	}
	for _, c := range real {
		if ip, ok := parseAny(c.service, c.line); !ok || ip != client {
			t.Errorf("%s: got %q %v from %q", c.service, ip, ok, c.line)
		}
	}
}
