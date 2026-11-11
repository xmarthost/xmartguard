package scanner

import (
	"bytes"
	"regexp"
	"strings"
)

// bitepestcontrol.com (superfast, 2026-11-06): a stolen administrator
// login installed a file manager plugin and dropped admin.php (fetches a
// file from GitHub and evals it), sd.php (a JPEG with PHP after it that
// fetches a text file and evals it), 1.php (an unauthenticated file
// manager dressed as a plugin, "PNG Optimizer Pro"), and the Alfa shell's
// CGI and SSI parts (1337_DATA/alfacgiapi/perl.alfa,
// alfa_shtml/alfa_ssi.shtml and the .htaccess that turns SSI on). None
// had a finding, and .shtml and .alfa files were not even read.

var (
	// eval of fetched code: eval('?>' . $x) runs a whole PHP file.
	reEvalFetched = regexp.MustCompile(`(?i)\beval\s*\(\s*(['"])\?>['"]\s*\.\s*\$[^\s.;)]+`)
	reFetchRemote = regexp.MustCompile(`(?i)\bcurl_exec\s*\(|\bfile_get_contents\s*\(\s*(?:['"]https?://|\$\w*(?:url|link|src|remote|host)\w*\s*[,)])|\bfopen\s*\(\s*['"]https?://|\bstream_get_contents\s*\(`)
	// $x = curl_exec(...); ... eval($x)
	reCurlVar = regexp.MustCompile(`\$(\w+)\s*=\s*curl_exec\s*\(`)

	// An unauthenticated file manager: what it does is driven by the
	// request (path, delete, chmod, unzip…).
	reFMParam = regexp.MustCompile(`(?i)\$_(?:GET|POST|REQUEST)\s*\[\s*['"](?:path|dir|folder|cwd|go|delete|del|remove|rename|chmod|perm|edit|file_content|newfile|unzip|zip|mkdir|new_?folder|folder_name|file_name|file_path)['"]`)

	// SSI that runs a command or includes a file named by the visitor
	// (a variable set from the cookie or query).
	reSSIVarExec = regexp.MustCompile(`(?i)<!--#(?:exec\s+cmd|include\s+virtual|include\s+file)\s*=\s*["']?\$\w+`)
	reSSIFromReq = regexp.MustCompile(`(?i)<!--#set\s+var\s*=\s*["']?\w+["']?\s+value\s*=\s*["']?\$(?:HTTP_COOKIE|QUERY_STRING(?:_UNESCAPED)?|HTTP_\w+|REQUEST_URI)`)

	// A Perl CGI that runs what the request sends.
	rePerlRunsInput = regexp.MustCompile(`(?s)\b(?:system|exec)\s*\(?\s*(?:decode_base64\s*\(\s*)?\$(?:in|FORM|form|input|params?|query|cgi|q)\s*(?:\{|->)|` + "`" + `[^` + "`" + `]{0,40}\$(?:in|FORM|form)\{`)
)

// remoteCodeEval: code fetched from another site and evaluated.
func remoteCodeEval(s []byte) bool {
	if !reFetchRemote.Match(s) {
		return false
	}
	if reEvalFetched.Match(s) {
		return true
	}
	for _, m := range reCurlVar.FindAllSubmatch(s, 5) {
		if regexp.MustCompile(`\beval\s*\(\s*\$` + regexp.QuoteMeta(string(m[1])) + `\b`).Match(s) {
			return true
		}
	}
	return false
}

// openFileManager: a file manager without any login check (a site's own
// managers, Tiny File Manager and the plugins check a login or a token).
func openFileManager(s []byte) bool {
	if !bytes.Contains(s, []byte("move_uploaded_file")) || reAuth.Match(s) || reClassDef.Match(s) {
		return false
	}
	ops := 0
	for _, r := range reFileOps {
		if r.Match(s) {
			ops++
		}
	}
	return ops >= 5 && len(reFMParam.FindAll(s, 6)) >= 4
}

// shellKit judges the Alfa shell's parts and other non-PHP shells.
func shellKit(path, ext string, content []byte) *Detection {
	low := strings.ToLower(path)
	// The Alfa shell writes its CGI and SSI helpers into these folders.
	if strings.Contains(low, "/alfacgiapi/") || strings.Contains(low, "/alfa_shtml/") || strings.Contains(low, "/alfa_data/") {
		return &Detection{CatVirus, "Webshell.Alfa.Component"}
	}
	switch ext {
	case ".shtml", ".shtm", ".stm", ".html", ".htm":
		if bytes.Contains(content, []byte("<!--#")) && reSSIVarExec.Match(content) && reSSIFromReq.Match(content) {
			return &Detection{CatVirus, "SSI.Webshell.Exec"}
		}
	}
	if bytes.HasPrefix(content, []byte("#!")) {
		line, _, _ := bytes.Cut(content[:min(len(content), 200)], []byte("\n"))
		if bytes.Contains(line, []byte("perl")) && rePerlRunsInput.Match(content) {
			return &Detection{CatVirus, "Perl.Webshell.CGI"}
		}
	}
	return nil
}
