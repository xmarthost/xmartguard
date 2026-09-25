// Package panel installs the WHM and cPanel plugins and serves their pages.
// The plugins contain no logic of their own: the page talks to the agent's
// local socket through this binary, and the agent decides what the caller
// (identified by uid) may do.
package panel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/local"
)

//go:embed ui.html
var uiHTML string

// Icon is the plugin icon (both panels).
const Icon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><path fill="#132046" d="M24 3 6 10v12c0 11 7.7 20.6 18 23 10.3-2.4 18-12 18-23V10z"/><path fill="#22c55e" d="m21 32-8-8 3-3 5 5 11-11 3 3z"/></svg>`

// BinPath is the agent binary the plugin pages execute.
const BinPath = "/opt/xmartguard/bin/xmartguard-agent"

// root lets tests install into a scratch tree.
func root() string {
	if r := os.Getenv("XG_CPANEL_ROOT"); r != "" {
		return r
	}
	return "/"
}

func p(rel string) string { return filepath.Join(root(), rel) }

// OptOutPath disables automatic plugin installation when it exists.
const OptOutPath = "/etc/xmartguard/no-panel-plugin"

// EnsureBin makes BinPath point at the running agent (installs from before
// 0.3.0 kept the binary in /usr/local/bin).
func EnsureBin() error {
	if root() != "/" {
		return nil
	}
	if _, err := os.Stat(BinPath); err == nil {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(BinPath), 0o755); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(filepath.Dir(BinPath)), 0o755)
	return os.Symlink(self, BinPath)
}

// Detected reports whether cPanel/WHM is installed.
func Detected() bool {
	_, err := os.Stat(p("usr/local/cpanel/version"))
	return err == nil
}

// Installed reports whether our WHM plugin is present.
func Installed() bool {
	_, err := os.Stat(p("usr/local/cpanel/whostmgr/docroot/cgi/xmartguard/index.cgi"))
	return err == nil
}

// Page renders the plugin page. fragment omits <html> (cPanel adds its own chrome).
func Page(mode string, fragment bool) string {
	ui := strings.Replace(uiHTML, "__MODE__", mode, 1)
	if fragment {
		return ui
	}
	return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>XMart Guard</title></head><body style="margin:0;background:#f1f5f9">` + ui + `</body></html>`
}

const whmCGI = `#!/bin/sh
#WHMADDON:xmartguard:XMart Guard
# Managed by XMart Guard; regenerated on every agent start.
exec ` + BinPath + ` panel-cgi --mode whm
`

const appConfig = `# XMart Guard WHM plugin (managed by xmartguard-agent)
name=xmartguard
service=whostmgr
user=root
url=/cgi/xmartguard/index.cgi
entryurl=xmartguard/index.cgi
acls=all
displayname=XMart Guard
icon=xmartguard.svg
target=_self
`

// The cPanel page runs as the logged-in account. It only relays the request
// to the agent binary, which connects to the local socket as that user.
const cpanelPHP = `<?php
// XMart Guard cPanel plugin (managed by xmartguard-agent; do not edit).
$bin = '` + BinPath + `';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) {
        http_response_code(415);
        echo '{"ok":false,"error":"content-type must be application/json"}';
        exit;
    }
    $req = file_get_contents('php://input', false, null, 0, 1048576);
    $proc = proc_open([$bin, 'panel-api'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        echo '{"ok":false,"error":"XMart Guard is not installed correctly"}';
        exit;
    }
    fwrite($pipes[0], $req);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    echo $out !== '' ? $out : '{"ok":false,"error":"no response from XMart Guard"}';
    exit;
}
require_once '/usr/local/cpanel/php/cpanel.php';
$cpanel = new CPANEL();
echo $cpanel->header('XMart Guard');
$page = shell_exec(escapeshellarg($bin) . ' panel-cgi --mode cpanel --fragment --raw');
echo $page !== null ? $page : '<p>XMart Guard is not installed correctly.</p>';
echo $cpanel->footer();
$cpanel->end();
`

const installJSON = `[{"type":"link","id":"xmartguard","name":"XMart Guard","group_id":"security","order":1,` +
	`"uri":"xmartguard/index.live.php","target":"_self","searchtext":"xmartguard malware virus scan security",` +
	`"icon":"xmartguard.svg","featuremanager":true}]`

func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		_ = os.Chmod(path, mode)
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".xgtmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}

func runTool(args ...string) error {
	tool := p(args[0])
	if _, err := os.Stat(tool); err != nil {
		return fmt.Errorf("%s not found", args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, tool, args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", filepath.Base(tool), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pluginTarball is what cPanel's install_plugin expects: install.json + icon.
func pluginTarball() ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{{"xmartguard/install.json", installJSON}, {"xmartguard/xmartguard.svg", Icon}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), ModTime: time.Unix(0, 0)}); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Install writes (or refreshes) both plugins. Registration with cPanel only
// runs when files changed, so calling it on every agent start is cheap.
func Install() ([]string, error) {
	if !Detected() {
		return nil, errors.New("cPanel/WHM is not installed on this server")
	}
	var done []string
	var errs []string
	// WHM (root)
	c1, err := writeIfChanged(p("usr/local/cpanel/whostmgr/docroot/cgi/xmartguard/index.cgi"), whmCGI, 0o700)
	if err != nil {
		return nil, err
	}
	c2, _ := writeIfChanged(p("usr/local/cpanel/whostmgr/docroot/addon_plugins/xmartguard.svg"), Icon, 0o644)
	c3, err := writeIfChanged(p("var/cpanel/apps/xmartguard.conf"), appConfig, 0o600)
	if err != nil {
		return nil, err
	}
	if c1 || c2 || c3 {
		if err := runTool("usr/local/cpanel/bin/register_appconfig", p("var/cpanel/apps/xmartguard.conf")); err != nil {
			errs = append(errs, err.Error())
		}
	}
	done = append(done, "WHM plugin: WHM » Plugins » XMart Guard")

	// cPanel (every account, Jupiter theme)
	themes := []string{"jupiter"}
	for _, theme := range themes {
		dir := p("usr/local/cpanel/base/frontend/" + theme)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		changed, err := writeIfChanged(filepath.Join(dir, "xmartguard/index.live.php"), cpanelPHP, 0o644)
		if err != nil {
			return done, err
		}
		marker := p("var/cpanel/apps/xmartguard.cpanel." + theme)
		if _, err := os.Stat(marker); err != nil || changed {
			tgz, err := pluginTarball()
			if err != nil {
				return done, err
			}
			tmp := p("var/cpanel/apps/xmartguard-plugin.tar.gz")
			if err := os.WriteFile(tmp, tgz, 0o600); err != nil {
				return done, err
			}
			if err := runTool("usr/local/cpanel/scripts/install_plugin", tmp, "--theme", theme); err != nil {
				errs = append(errs, err.Error())
			} else {
				_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
			}
			os.Remove(tmp)
		}
		done = append(done, "cPanel plugin ("+theme+"): Security » XMart Guard")
	}
	if len(errs) > 0 {
		return done, errors.New(strings.Join(errs, "; "))
	}
	return done, nil
}

// Uninstall removes both plugins.
func Uninstall() error {
	var errs []string
	if _, err := os.Stat(p("var/cpanel/apps/xmartguard.conf")); err == nil {
		if err := runTool("usr/local/cpanel/bin/unregister_appconfig", "xmartguard"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, theme := range []string{"jupiter"} {
		marker := p("var/cpanel/apps/xmartguard.cpanel." + theme)
		if _, err := os.Stat(marker); err == nil {
			if tgz, err := pluginTarball(); err == nil {
				tmp := p("var/cpanel/apps/xmartguard-plugin.tar.gz")
				if os.WriteFile(tmp, tgz, 0o600) == nil {
					if err := runTool("usr/local/cpanel/scripts/uninstall_plugin", tmp, "--theme", theme); err != nil {
						errs = append(errs, err.Error())
					}
					os.Remove(tmp)
				}
			}
			os.Remove(marker)
		}
		os.RemoveAll(p("usr/local/cpanel/base/frontend/" + theme + "/xmartguard"))
	}
	os.RemoveAll(p("usr/local/cpanel/whostmgr/docroot/cgi/xmartguard"))
	os.Remove(p("usr/local/cpanel/whostmgr/docroot/addon_plugins/xmartguard.svg"))
	os.Remove(p("var/cpanel/apps/xmartguard.conf"))
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// ServeCGI handles one CGI request (WHM runs index.cgi as root).
// GET returns the page; POST {action, params} is relayed to the agent.
func ServeCGI(mode string, fragment, raw bool, env func(string) string, in io.Reader, out io.Writer) {
	header := func(ct string, status int) {
		if raw {
			return
		}
		if status != 200 {
			fmt.Fprintf(out, "Status: %d\r\n", status)
		}
		fmt.Fprintf(out, "Content-Type: %s\r\nCache-Control: no-store\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n", ct)
	}
	jsonErr := func(status int, msg string) {
		header("application/json", status)
		b, _ := json.Marshal(local.Response{Error: msg})
		out.Write(b)
	}
	// WHM hands CGIs the logged-in user; resellers are not allowed in.
	if mode == "whm" && !raw {
		if u := env("REMOTE_USER"); u != "" && u != "root" {
			jsonErr(403, "XMart Guard is available to root only")
			return
		}
	}
	// --raw is only used by the cPanel page to render itself.
	if raw || env("REQUEST_METHOD") != "POST" {
		header("text/html; charset=utf-8", 200)
		io.WriteString(out, Page(mode, fragment))
		return
	}
	if !strings.HasPrefix(env("CONTENT_TYPE"), "application/json") {
		jsonErr(415, "content-type must be application/json")
		return
	}
	n, _ := strconv.Atoi(env("CONTENT_LENGTH"))
	if n <= 0 || n > 1<<20 {
		jsonErr(400, "invalid request")
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(in, body); err != nil {
		jsonErr(400, "invalid request")
		return
	}
	header("application/json", 200)
	out.Write(Relay(body))
}

// Relay forwards a request body to the agent and returns a JSON response.
func Relay(body []byte) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	data, err := local.CallRaw(ctx, body)
	var resp local.Response
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.OK, resp.Data = true, data
	}
	b, _ := json.Marshal(resp)
	return b
}
