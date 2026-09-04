# How-To: Ship Greenbone findings to Graylog (GELF)

> **Summary.** The GELF emitter turns normalized vulnerability findings into GELF 1.1 messages and ships them to a Graylog GELF input. **Use TCP, not UDP** — a burst of findings overruns the UDP socket buffer and silently drops messages (measured 36% loss on 366 findings). Vulnerability data is completeness-critical (a dropped Critical is a missed Critical), so reliability wins.

## Pipeline

```
greenbone_collector.py  (read-only GMP pull -> normalized JSONL)
        |
gelf_emitter.py --tcp   (JSONL -> GELF 1.1 -> Graylog)
        |
Graylog GELF TCP input :12201  -> indexed, searchable
```

## The Graylog input (one-time)

Create a **GELF TCP** input (`org.graylog2.inputs.gelf.tcp.GELFTCPInput`):
- port **12201**, bind `0.0.0.0`, global
- `use_null_delimiter: true` (the emitter null-terminates each message)
- `tls_enable: false` (LAN; enable if crossing trust boundaries)

Additive — it does not touch the existing Syslog UDP :1514 input. Verify state is `RUNNING` before sending.

## Field mapping

Each finding becomes GELF with:
- `short_message` = `[<threat>/<severity>] <nvt> on <host>`
- `timestamp` = the scan_end epoch (so events sort by when the scan ran, **not** ingest time — search a wide window, e.g. 48h)
- `level` = severity→syslog: CVSS ≥9 → 2 (Crit), ≥7 → 3 (High), ≥4 → 4 (Med), else 6 (Low)
- custom fields (underscore-prefixed in GELF; **Graylog strips the underscore on index**): `_severity`→`severity`, `_vuln_host`→`vuln_host`, `_cve`, `_cvss_vector`, `_nvt_oid`, `_scan_task`, `_qod`, etc.

## Pitfalls (learned the hard way)

1. **UDP drops on burst.** Sending hundreds of datagrams at once loses a large fraction (36% measured). Use `--tcp`. UDP's fire-and-forget suits high-rate syslog where a lost line is noise; it is wrong for batch vuln pulls.
2. **Search by the un-underscored field name.** Send `_severity`, query `severity`. Querying `_severity` returns 0 and looks like data loss when it isn't.
3. **Timestamp is scan_end, not now.** Findings carry the scan's completion time. A 5-minute search window shows nothing; widen to 24-48h.
4. **CVE queries need escaping.** `cve:CVE-2026-1234` tokenizes on the hyphen; escape it (`CVE\-2026\-1234`) or use a quoted/keyword search.

## Verification (2026-08-16)

- Sent 366 via TCP → input `incomingMessages` = 366 (zero loss; UDP prior run lost 133).
- Searchable: `event_type:vulnerability`, `severity:>=7` → 82 High, all resolve with full fields.

## Usage

```
python3 collector/gelf_emitter.py --in findings.jsonl \
  --graylog-host <GRAYLOG_HOST> --port 12201 --tcp \
  --source-host greenbone-scanner
# preview without sending:
python3 collector/gelf_emitter.py --in findings.jsonl --graylog-host x --dry-run
```

*Source of truth: `private implementation repository`. Last reviewed: 2026-08-16.*
