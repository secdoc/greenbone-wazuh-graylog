# How-To: Greenbone API Access (GMP over SSH)

> **Summary.** The Greenbone Community Edition (Docker) exposes GMP only on a local unix socket, not on the network. This is how the pipeline reaches it read-only: an SSH user in the `docker` group on the scanner host, the gvmd socket (bind-mounted to the host), forwarded over SSH to the automation host, and spoken with `python-gvm`. No network exposure of GMP, no changes to the Greenbone stack.

## Prerequisites

- SSH user on the scanner host in the `docker` group (or a restricted sudoers rule for the gvmd exec).
- A GMP account (username/password) on the Greenbone server.
- `python-gvm` on the automation host.

## Key facts about this build

- Greenbone Community Edition, Docker Compose. Containers: `gvmd`, `gsad`, `ospd-openvas`, `openvasd`, `pg-gvm`, `redis`, `nginx`. **No `gvm-tools` container** in this build.
- GMP version: **22.7**.
- The gvmd socket is **bind-mounted to the host** at `/tmp/gvm/gvmd/gvmd.sock` (visible in `docker inspect gvmd ... Mounts`: `bind /tmp/gvm/gvmd -> /run/gvmd`). This means you can reach it from the host directly, no `docker exec` needed.

## Connection method

1. **Forward the socket** from the scanner host to the automation host over SSH:
   ```
   ssh -i <key> -N -L /local/path/gvmd.sock:/tmp/gvm/gvmd/gvmd.sock <user>@<SCANNER_HOST>
   ```
2. **Speak GMP** with `python-gvm` over the forwarded unix socket. **Note:** python-gvm 27.x returns **XML strings**, not Element objects — parse with `xml.etree.ElementTree`.
   ```python
   import xml.etree.ElementTree as ET
   from gvm.connections import UnixSocketConnection
   from gvm.protocols.gmp import Gmp
   conn = UnixSocketConnection(path="/local/path/gvmd.sock", timeout=40)
   with Gmp(connection=conn) as gmp:
       ET.fromstring(gmp.get_version())            # 200 OK, no auth
       ET.fromstring(gmp.authenticate(user, pw))   # 200 OK
       ET.fromstring(gmp.get_reports(filter_string="rows=1 sort-reverse=date"))
   ```

## Pitfalls

- **Raw `socat` piping fails.** Sending GMP XML via `socat ... | ssh` closes the socket on stdin EOF before gvmd replies. Use python-gvm (it holds the session), not one-shot socat pipes.
- **`python3-venv` may be missing on the scanner host** (Debian splits it out). Don't install packages on the scanner — run python-gvm on the automation host over the forwarded socket instead. Keeps the scanner untouched.
- **`gvm-cli`/`gvm-tools` are NOT in the gvmd container** in this build. Don't rely on them; go straight to the socket.

## Object visibility (ownership scoping) — IMPORTANT

GVM scopes every task/target/report to its **owner**. A new user (even with the Admin *role*) sees **0 tasks / 0 reports** for objects owned by another user (e.g. `admin`). This is NOT data loss — it is ownership scoping. Confirmed 2026-08-16: 9 weekly scan tasks + 37 reports were fully intact under `admin` while `<SVC_USER>` saw none.

**Sharing must be done BY the owner (admin), not the recipient.** The recipient can't see the owner's users/objects, so it cannot self-grant.

### What works (verified)

- A resourceless `get_tasks` *command* permission alone is **not** enough — the user can call the command but still only sees objects it owns.
- **Resource-scoped permissions ARE what work:** as admin, grant `create_permission(name="get_tasks", subject=user <SVC_USER>, resource=<task_id>, resource_type="task")` for each task. Reports linked to those tasks then become visible too. After this, `<SVC_USER>` saw all 9 tasks and 37 reports and could read full results (findings).

### Privilege note (hardening)

`<SVC_USER>` currently has the **Admin role**, so it also has **write** capability (verified: it could create/delete a target). The collector only ever issues read commands, but for true least-privilege the account should later be downgraded from Admin to a limited role and rely solely on the resource-scoped read permissions. Tracked as a hardening item.

## Verification (2026-08-16)

- SSH login OK as `<SVC_USER>` (uid in `docker` group).
- GMP `get_version` → 22.7, status 200. `authenticate` → 200 OK.
- **State:** 0 tasks / 0 reports — no scans have been run yet, so a scan must be created to produce findings for the pipeline.

*Source of truth: `private implementation repository`. Last reviewed: 2026-08-16.*
