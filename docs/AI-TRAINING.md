# AI scanner and how the scanner is trained

## What the AI does (0.23.9)

The AI scanner is a real AI only: the agent sends a file (an excerpt of
it) to the portal, which asks the AI APIs configured under AI Scanner
(Gemini, Groq, OpenRouter, ...), with failover between keys, and shares
every verdict with all linked servers. There is no offline model any more
(the built-in logistic model, `ai-train`, `ai-score` and the "fleet
model" were removed in 0.23.9).

The AI only comments. Its verdict and reason are shown next to each
detection; it never restores a file, never clears content and teaches
nothing by itself (0.23.8). The AI called the fake-plugin campaign's
files "backup" and "security" plugins more than a hundred times while the
same model called other copies malicious.

| Signal | Effect |
|---|---|
| AI says clean | A comment only: the file stays where the scanner put it and is still flagged |
| AI says malicious (>= 80 %) | With "Act on confident verdicts" the virus action is applied ("Only advise" turns this off) |
| Administrator restores a file | That exact content is not flagged again on this server |
| Administrator sets a verdict in AI Scanner » Shared knowledge | Clean: cleared on every server. Malicious: a hash detection on every server (`XG.AI.Learned`) |

## How the scanner is trained

"Trained" means the signature engine: behaviour rules and families,
known-good lists (WordPress core and plugin checksums), known-bad hashes
and YARA. It improves from reviewed cases, never on its own:

1. Review the AI's comments against the files (daily): the connector's
   `ai_knowledge` and `list_findings` show the verdict and reason,
   `get_finding_content` the file.
2. Set the true verdict in Shared knowledge (fleet-wide hash decision).
3. For a wrong rule (a false positive class or missed malware), the rule
   is fixed in the engine with an inert regression fixture
   (`agent/internal/scanner/fleetfp_test.go`, `families_test.go`) and
   released, so every server and every new server handles that kind of
   file.

Measure before a release: `xpguard-agent check /path --misses` (and
`--no-hash` for the rules alone) on a malware corpus and on clean
projects (see SIGNATURES.md).
