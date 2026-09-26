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
