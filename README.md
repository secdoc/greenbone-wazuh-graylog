# greenbone-wazuh-graylog

Wire a **Greenbone / OpenVAS** vulnerability scanner into a SIEM as a first-class lane: a
read-only collector pulls GMP scan results, normalizes each finding, and delivers to **both
Graylog** (retention/hunting) and **Wazuh** (detection), with **Wazuh decoders + rules** that
parse the findings and a ready-to-import **Wazuh/OpenSearch vulnerability dashboard**.

> Sanitized, adaptable reference. Placeholders (`<SCANNER_HOST>`, `<GRAYLOG_HOST>`,
> `<WAZUH_HOST>`, `<GMP_USER>`, RFC5737 example networks) stand in for real values. Carries
> no real environment data. Companion to the broader
> [soc-pipeline](https://github.com/secdoc/soc-pipeline-public) build and its siblings
> [socfortress-waf-siem](https://github.com/secdoc/socfortress-waf-siem) and
> [technitium-wazuh-graylog](https://github.com/secdoc/technitium-wazuh-graylog).

## Why this exists

A vulnerability scanner whose findings only live in its own console never reaches the analyst
correlating an alert. This treats Greenbone as one source in your existing pipeline: the same
`log -> event -> alert -> incident` path as every other feed. Graylog keeps full-volume findings
for hunting; Wazuh gets a rule-gated subset for detection, and the same finding on a host that
also fired an IDS/auth alert becomes a higher-priority incident.

## Architecture (parallel consumers, not a chain)

```
  Greenbone (GMP over SSH)  -->  greenbone_collector.py (read-only, incremental)
                                      |  normalize each finding once
                        +-------------+--------------------------+
                        v                                        v
             Graylog (GELF/TCP)                       Wazuh manager localfile
             retention + hunting                      detection (decoders + rules 115xxx)
```

Do **not** chain source -> Graylog -> Wazuh: Graylog reformats and breaks Wazuh decoders.
Both consumers get the normalized finding independently.

## What's in here

| Path | What |
|------|------|
| `collector/greenbone_collector.py` | Read-only GMP pull + normalize to flat JSON findings |
| `collector/gelf_emitter.py` | Ship findings to Graylog as GELF (UDP chunked / TCP) |
| `collector/run_pipeline.py` | One-cycle runner: collect -> Graylog + Wazuh localfile |
| `wazuh/decoders/greenbone_decoders.xml` | Decoder slot (placeholder — see "Message parsing" below) |
| `wazuh/rules/greenbone_rules.xml` | Detection rules (ID range 115xxx), CVSS -> level tiers |
| `scripts/wazuh_dashboard_gen.py` | Dashboard-as-code -> saved-objects NDJSON |
| `scripts/vuln_dashboard_gen.py` | Standalone HTML/SVG vuln dashboard generator |
| `docs/wazuh-vuln-dashboard.ndjson` | Prebuilt dashboard, import-ready |
| `docs/how-to-*.md` | Walkthroughs: GMP access, GELF emitter, Wazuh rules, dashboard |
| `scripts/scrub_check.py` | Public-safety gate (run before every commit) |
| `samples/greenbone-findings-sample.jsonl` | SYNTHETIC sample findings |

## Message parsing (Graylog vs Wazuh)

The collector emits **structured** JSON/GELF, so parsing is minimal by design, parse once at the
structured source and let each consumer key on typed fields rather than re-parsing text:

- **Graylog:** no extractors or pipeline rules needed. GELF custom fields arrive already typed and
  searchable on the input.
- **Wazuh:** the built-in **`json` decoder** extracts every field from the finding
  (`decoded_as: json`); no custom decoder is required. `wazuh/decoders/greenbone_decoders.xml` is
  therefore an intentional **placeholder** (documented no-op) kept for repo symmetry, a custom
  decoder with `use_own_name` would actually *replace* native JSON extraction and break field
  matching. The real detection logic is in `wazuh/rules/greenbone_rules.xml`, which matches on the
  json-decoded `<field name="...">` values and maps CVSS to alert level.

## Severity mapping (CVSS -> Wazuh level)

`CVSS >= 9 -> level 12 (Critical)`, `>= 7 -> 10 (High)`, `>= 4 -> 5 (Medium)`, else `3 (Low)`.
Rule IDs live in the `115000-115999` range (no collision with other lanes).

## Quick start

```bash
cp .env.example .env      # fill in SCANNER/GRAYLOG/WAZUH + GMP creds (never commit real .env)
python3 collector/run_pipeline.py --dry-run     # pull + normalize, no delivery
python3 collector/run_pipeline.py               # deliver findings to Graylog + Wazuh
python3 scripts/wazuh_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' \
    --out docs/wazuh-vuln-dashboard.ndjson      # regenerate the dashboard NDJSON
```

Full walkthroughs in [`docs/`](docs/): GMP-over-SSH access, the GELF emitter, the Wazuh rules,
and the dashboard import.

## License

Dual-licensed: code under Apache-2.0 (`LICENSE`), docs/diagrams under CC BY 4.0
(`LICENSE-docs`). Attribution required under both. See `LICENSING.md` and `NOTICE`.

*Greenbone/OpenVAS and Wazuh/Graylog are their respective projects' trademarks; this is an
independent integration.*

## GitLab CI baseline

GitLab CI validates tracked JSON, Python, and shell syntax, then runs a network-independent high-confidence secret scan across full Git history. The public pipeline contains no private registry, runner, credential, CA, or internal-domain reference.

