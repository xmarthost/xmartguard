# Training the built-in AI scanner

The AI scanner's default provider is XMart Guard's own model: a logistic
regression over code features (function calls, request variables, code at
the top/bottom of a file, obfuscation measurements). It is free, runs inside
the agent and sends nothing anywhere. It only judges files the signature
engine already marked **suspicious**, so it never floods a server with false
alarms.

The model improves with more real quarantine data. To retrain:

1. Collect quarantined malware from your servers into one folder (for
   example `/opt/xmartguard/data/quarantine` from several servers, or another
   product's quarantine). Encoded/binary quarantine files are skipped
   automatically.
2. Collect clean code: current WordPress releases, popular plugins/themes,
   Joomla, OpenCart, Laravel … (one folder per project).
3. Train:

   ```sh
   xmartguard-agent ai-train -v \
     --malicious /path/to/quarantine \
     --clean /path/to/wordpress --clean /path/to/woocommerce --clean /path/to/joomla \
     --out /etc/xmartguard/ai-model.bin
   ```

   The command prints the held-out detection rate and false-positive rate and
   lists the worst mistakes for review. Quarantine files that are identical
   to clean code, or named like a clean library file that the signature
   engine does not flag, are dropped as probable false positives of the tool
   that quarantined them.
4. Restart the agent (`systemctl restart xmartguard-agent`) to use
   `/etc/xmartguard/ai-model.bin`; without it the model shipped in the agent
   is used. `xmartguard-agent ai-score FILE…` shows a file's score and the
   strongest indicators.

To ship a retrained model to every server, write it to
`agent/internal/ml/model.bin` and release a new agent.

Reference model (v0.5.0): 411 unique malicious files from a real quarantine
and ~50,000 clean files (WordPress 6.5–7.x, WooCommerce, Jetpack, Elementor,
Yoast, Joomla, Drupal, Magento, OpenCart, PrestaShop, Laravel, Moodle,
Nextcloud, phpMyAdmin, Roundcube …). Held out: 87% detected at 0.05% false
positives (suspicious threshold).

## Fleet training (0.6)

Besides retraining the shipped model from quarantine data, every server can
learn continuously from the AI APIs configured in the portal:

1. With "Learn from all servers" on, the agent sends the built-in model's
   feature indices and its logit (`z`) with each file it asks the portal AI
   about. File contents are not stored for training.
2. AI verdicts of at least 80% (malicious or clean) become training samples
   (`ai_samples`); an administrator's correction in AI Scanner » Shared
   knowledge overrides the label.
3. Once there are at least 5 malicious and 5 clean examples (learning from
   malicious files alone would raise the score of every PHP file), every 5
   minutes (or with "Train fleet model now") the portal trains a small
   update on top of the base model: logistic regression on `z + Σ delta`,
   class-balanced, L2-decayed and clamped to ±3 per weight so a single wrong
   verdict cannot swing it. Only weights that changed are kept.
4. Agents download the update with the shared verdicts every 10 minutes and
   score with `base + delta` (model version `<base>+fleet.<n>`). Malicious
   verdicts of at least 90% also become hash detections (`XG.AI.Learned`).

When a new agent release ships a retrained base model, samples are kept per
base version and the update is trained again for the new base as servers send
files.

## Making detection better (research notes, 0.7)

What reduces false positives most is not a smarter model but knowing which
files are genuine: official checksums for WordPress core (every release and
beta) and WordPress.org plugins, the same approach Wordfence uses. XMart
Guard now trusts those files outright and repairs modified core files from
the official release.

For the model itself, published work on PHP web shells points to:

- **Opcode / AST features** instead of raw tokens (PHP VLD opcode n-grams,
  simplified syntax trees) resist obfuscation better; a future agent could
  extract them with `php -d vld…` where PHP is installed.
- **Long files**: attention over sliding windows beats truncation; our
  excerpt (start, end, windows around risky calls) follows the same idea for
  the AI APIs.
- **Incremental learning** from newly confirmed samples, with balanced
  benign examples, keeps a model current; the fleet model does this with AI
  verdicts and needs clean examples as much as malicious ones (hence the
  5 + 5 minimum).
- **Data**: benign code from real frameworks (WordPress, plugins) matters as
  much as malware. Quarantine data from your servers (malicious) plus the
  AI's "clean" verdicts on detections (hard negatives) are the most useful
  training material; send quarantine archives to retrain the shipped model
  with `xmartguard-agent ai-train`.

## How verdicts feed back into detection

| Signal | Where it is stored | Effect |
|---|---|---|
| Administrator restores a file | Agent: `ai_verdicts` (source `admin`, sha256) | That exact content is never flagged again on this server; any change is scanned again |
| "Clear (false positive)" | Portal: `ai_kb` clean, overridden | Every server skips that content; the fleet model retrains on it |
| Online AI says clean (≥90%) | Agent + portal `ai_kb` | File restored automatically; hash known clean on all servers |
| Online AI says malicious (≥90%) | Portal `ai_kb` | Becomes a hash detection on every server within 10 minutes |
| Every AI verdict with features | Portal `ai_samples` | Hourly retraining of the fleet update of the built-in model |

The AI's *reason* text is kept for people (Scanner Logs, AI Scanner »
Shared knowledge, MCP). The learning itself uses the verdict, the
confidence and the file's features; the reason is not parsed.

## Roadmap for better detection

1. **Labelled corpus** — keep collecting quarantine samples (malicious) and
   restored/cleared files (clean) from real servers; restored files are the
   most valuable clean samples because they are exactly the false positives.
2. **FP regression suite** — every reported false positive becomes a case in
   `families_test.go`/`heuristics` tests before the rule is changed.
3. **Clean-code baseline** — official plugin/theme checksums from
   WordPress.org (already used for core and plugins), extended to popular
   premium plugins by hashing the copies seen on many servers with no
   detections (fleet reputation).
4. **Retrain on reasons** — group AI reasons by family (loader, uploader,
   SEO spam…) and turn frequent families into behaviour rules with tests.
5. **Measure** — `xmartguard-agent check --misses --no-hash` on the malware
   corpus (target >95% rules-only) and on clean corpora (target 0 virus
   hits) before every release.
6. **AI review over MCP** — an assistant connected through the AI Connector
   reviews low-confidence verdicts and new detections across the fleet and
   proposes rule changes, which are released only after the tests above.
