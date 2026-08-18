# How-To: Wazuh rules for Greenbone vulnerability findings

> **Summary.** Feed the collector's JSON findings into Wazuh via a `localfile`
> with `log_format=json`; Wazuh's BUILT-IN `json` decoder extracts every field.
> Rules in a dedicated ID range (115000-115999) gate alerts by severity. No
> custom decoder — a custom one breaks the native JSON extraction.

## Ingest (localfile)

Add to `ossec.conf` (or a shared agent config) pointing at the collector output:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/greenbone-findings.jsonl</location>
</localfile>
```

## Rules (severity ladder)

Range **115000-115999** (chosen clear of the UniFi 100001-110203 range — no collision).

| Rule | Match | Level | Tier |
|------|-------|-------|------|
| 115000 | base: `event_type=vulnerability` + `source=greenbone` | 0 | recorded, not alerted |
| 115010 | `threat=Low` | 2 | archive / enrichment |
| 115020 | `threat=Medium` | 5 | visible, no page |
| 115030 | `threat=High` | 10 | **alert** |
| 115040 | `severity` `^9|^10` (CVSS ≥9) | 12 | **high alert** |

Verified live via `wazuh-logtest`: 2.6→115010/L2, 5.0→115020/L5, 7.5→115030/L10, 9.8→115040/L12.

## Pitfalls (learned building this)

1. **Do NOT write a custom decoder for JSON input.** A `<decoder>` with
   `<use_own_name>true</use_own_name>` and a `prematch` REPLACES Wazuh's native
   JSON field extraction — Phase 2 shows the decoder name but extracts **no
   fields**, so no rule matches. Delete it; let the built-in `json` decoder run,
   then match fields with `<decoded_as>json</decoded_as>` + `<field name="...">`.
2. **JSON numbers render as float strings.** `severity: 9.8` decodes as
   `9.800000`. Match Critical with `^9|^10`, not `>=9` or `9.0`.
3. **Wazuh fires ONE rule per event** (best match). Don't build competing sibling
   rules for the same event (e.g. a separate "has-CVE" rule) expecting both to
   fire — fold that context into the tier rule's description instead.
4. **Static decoded fields need their native element.** `dstip`, `srcip`,
   `dstport` are static — use `<dstip>`/`<srcip>`/`<dstport>`, never
   `<field name="dstip" type="pcre2">` (raises "Field is static", the whole file
   fails to load). This build also accepts only ONE CIDR per element → split
   multi-CIDR matches into sibling rules.
5. **File load order matters for `if_sid`.** Wazuh loads `etc/rules/*.xml`
   alphabetically; a rule's `if_sid` parent must be defined in a file that loads
   EARLIER. Name files so dependencies load first (e.g. `unifi_traffic` before
   `unifi_traffic_threat`).

## Offline validation gate (non-disruptive)

Always validate before applying:
```
sudo /var/ossec/bin/wazuh-analysisd -t      # test-compile whole ruleset, no apply
echo '<json line>' | sudo /var/ossec/bin/wazuh-logtest   # functional match test
```
Only `systemctl restart wazuh-manager` after `analysisd -t` reports 0 errors.
Confirm non-disruption: a greenbone finding must decode as `json` (never `unifi-*`),
and existing sources must still fire.

*Source of truth: `secdoc/soc-pipeline`. Last reviewed: 2026-08-16.*
