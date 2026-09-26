# Signatures, known-good files and false positives

XMart Guard combines several engines. Order of checks for a script file:

1. **Known-good content (never flagged)**
   - *WordPress core*: the MD5 of every PHP/JS/HTML/text/image file of every
     WordPress release since 5.8 ships inside the agent (13,597 files from
     173 releases up to 7.1.2). The portal adds every new release, beta and
     release candidate twice a day (`api.wordpress.org/core/stable-check`,
     the releases page, the checksums API, and the release zip for betas).
   - *WordPress.org plugins*: files are compared with the official checksums
     of the installed version (`downloads.wordpress.org/plugin-checksums/…`),
     fetched through the portal and cached. Premium plugins have no public
     checksums and are scanned normally.
   - *Cleared content*: files the AI (≥90% clean, on any server) or an
     administrator found to be false positives.
2. **Known-bad hashes**: XMart Guard's own list, fleet-learned AI verdicts
   (`XG.AI.Learned`), Linux Malware Detect MD5 signatures.
3. **XMart Guard heuristics and rules** (own code; comments are ignored so
   documentation never triggers a rule).
4. **Linux Malware Detect hex patterns** (suspicious → confirmed by the AI).
5. **YARA**: the administrator's rules in `/etc/xmartguard/yara/*.yar`
   (virus) and public feed rules in `/etc/xmartguard/yara/feeds/` (suspicious).
6. **ClamAV**, when installed.

Measured on all 13,186 distinct script files of WordPress 5.8 – 7.1.2: **0
detections**, including before the known-good list applies.

## Behaviour families (0.7.2)

Rules describe what a file *does*, so renamed and re-encoded variants are
caught without a hash:

| Signature | Behaviour |
|---|---|
| `PHP.Loader.SilentInclude` / `IncludeNonPHP` / `HiddenInclude` | tiny loaders: `@is_file("…")` + `@include`, or include of an image/archive/log file or a hidden `.name.php` |
| `PHP.Loader.DecodedInclude` | `require` of a path computed by a character-building decoder |
| `PHP.Obfuscated.FunctionTable` | functions fetched by number: `f(40)($x)` |
| `PHP.Obfuscated.CharDecoder` | `chr(ord($s[$i]) ^ $k)` / `.= chr(…)` decoders feeding eval or a dynamic call |
| `PHP.Obfuscated.RandomIdentifiers`, `HashNamedVariables` | machine-generated variable names around an executor |
| `PHP.Obfuscated.EvalTemplate` | `eval("?>" . $decoded)` |
| `PHP.Obfuscated.SplitFunctionName` | `'gz'.'in'.'fla'.'te'` |
| `PHP.Dropper.WritableDirs`, `PHP.Dropper.SelfDeleting` | writes a decoded payload into every writable directory; tiny self-deleting writers |
| `PHP.Backdoor.WPAdminLogin`, `WPAdminCreator` | small scripts that load WordPress to log in as, or create, an administrator |
| `PHP.WebShell.FunctionBypass`, `ExecAlternatives` | `ini_set('disable_functions')`, tables of exec alternatives |
| `PHP.Injector.RemoteContent` | front-end hook echoing remote content fetched with `sslverify => false` |
| `PHP.SEO.UserAgentCloaking`, `PHP.SEO.Cloaking` | crawlers get a different page |
| `PHP.Config.AutoPrependLoader` | `.user.ini` / `php.ini` / `.htaccess` `auto_prepend_file` to a hidden or non-PHP file (Wordfence, NinjaFirewall, MalCare, Sucuri, Patchstack are allowed) |
| `Disguised.MarkupInImage` | HTML pages saved as `.jpg`/`.png` |

Heuristic hits in `/tests/` directories and `.phar` archives are reported as
suspicious (confirmed by the AI) instead of quarantined.

### Measuring detection

```bash
xmartguard-agent check /path --misses              # files NOT detected
xmartguard-agent check /path --misses --no-hash    # the rules alone, without the hash list
```

On a real quarantine of 2,162 files (2,100 genuinely malicious): the rules
alone detect 91.1% of the malware (76% in 0.7.1), 97.6% of all files with the
hash list. On 259,348 files of 22 clean projects (WordPress 7.1.2, Gutenberg,
WooCommerce, Jetpack, Elementor, Yoast, Drupal, Joomla, Magento, PrestaShop,
Laravel, Moodle, Nextcloud, phpMyAdmin, …): one quarantine-level hit
(VaultPress, which executes signed remote code by design and is trusted
through the WordPress.org plugin checksums), the rest suspicious-only in test
suites. The known-bad hash list was cleaned at the same time: 44 entries were
not malware (plugin translation files, and files corrupted by a partial disk
write whose remainder is the official WordPress file).

## Public feeds (configured on the portal: `SIG_FEEDS`)

| Feed | What | License |
|---|---|---|
| `lmd:https://cdn.rfxn.com/downloads/maldet-sigpack.tgz` | Linux Malware Detect (R-fx Networks): MD5 + hex signatures, `rfxn.yara` | GPLv2 |
| `yara:…/Neo23x0/signature-base/…/gen_webshells.yar` | Generic web shell rules (Arnim Rupp, Florian Roth) | Detection Rule License 1.1 |
| `yara:…/Neo23x0/signature-base/…/thor-webshells.yar` | Web shell family rules | Detection Rule License 1.1 |

The feeds are downloaded by the portal at run time (not bundled), YARA
`include` files are resolved into one file, and every agent compiles each
rule file before using it (a file that does not compile is skipped). Both
signature-base files produce no hit on any WordPress core file since 5.8.
php-malware-finder was evaluated and left out by default: it flags 833 of
13,186 WordPress core files (it is a hunting tool, not a detector).

Add a feed: `SIG_FEEDS=lmd:URL,yara:URL,…` in `deploy/.env`. Disable per
server: Settings » Virus Scanner » Public malware signatures (or
`xgcli feeds --disable`).

## Infected WordPress core files

With *Repair infected WordPress core files* (default on), a detected core
file is replaced by the official file of the site's version (read from
`wp-includes/version.php`), downloaded through the portal (which verifies
and caches it; sources: `core.svn.wordpress.org`, then the official GitHub
mirror) and checked against the official MD5. The infected copy stays in
quarantine; *Restore* brings it back.

## False positives

- The AI scanner judges detections. At ≥90% "clean" the file is restored
  from quarantine (status *cleared*), the verdict is shared with every server
  (the same content is never flagged again) and becomes a training example
  for the fleet model.
- By hand: Scanner Logs » *False positive* (or `xgcli log-action --clear
  --log-id ID`).
- Portal » AI Scanner » *Signatures the AI overruled* lists the engine rules
  the AI corrected most; they are the rules to tune.
