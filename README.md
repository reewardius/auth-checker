# auth_checker

A concurrent authorization-bypass checker for HTTP/JSON APIs. It runs a baseline
reachability check on every target and, on request, a set of bypass tests — JWT
forgery, JWT `kid` signature bypass, the Next.js `CVE-2025-29927` middleware
bypass, and proxy-path traversal — printing ready-to-paste `curl` PoCs and
writing findings to JSON. It can also discover endpoints directly from
Swagger/OpenAPI specs.

> **Authorized use only.** Run this only against systems you own or are
> explicitly permitted to test.

---

## Install

```bash
pip install requests     # required
pip install tqdm         # optional, only for the --tqdm progress bar
```

---

## Quick start

```bash
# Baseline check of a list of URLs
python3 auth_checker.py -f targets.txt

# All checks, results to JSON
python3 auth_checker.py -f targets.txt --full -o results.json

# Discover endpoints from Swagger specs, then check them
python3 auth_checker.py -f swagger_endpoints.txt --swagger --full -o results.json
```

`targets.txt`: one URL per line; blank lines and `#` comments are ignored; a line
without a scheme gets `http://`.

---

## Checks

The **baseline** check always runs: a response counts as OK only if it is status
`200`, `Content-Type` is `application/json` or `text/plain`, the body is
non-empty, and it is not a trivial health-check (`OK`/`HEALTHY`/`{"status":"ok"}`…).
An endpoint that is baseline-OK **without any token** is itself a finding.

The bypass tests below are opt-in. Each has a short **name** used by `--exclude`.

| Name | Enable with | What it does |
|------|-------------|--------------|
| `jwt` | `--jwt-test` | Forged JWTs: weak HMAC secret, `alg=none` (+ case variants), RS256→HS256 confusion, plus a garbage-signature negative control. |
| `kid` | `--jwt-kid-test` | Differential test — same forged token with vs. without a `kid` header; catches servers that skip signature validation when `kid` is present. |
| `nextjs` | `--check-nextjs-cve` | CVE-2025-29927 — Next.js middleware auth bypass via the `x-middleware-subrequest` header. |
| `proxy` | `--check-proxy-bypass` | Reaches a protected resource through an adjacent public proxy path using encoded path traversal; confirmed hits get a HIGH/MEDIUM/LOW severity from the leaked body. |

- `--full` enables `jwt`, `kid`, `nextjs`, and (if a map or `--paths` is given) `proxy`.
- `--exclude name1,name2` turns checks off **after** `--full` / individual flags, e.g. `--full --exclude kid,proxy`.

---

## Options

| Flag | Description |
|------|-------------|
| `-f, --file` | **Required.** Input file (targets, or Swagger UI URLs with `--swagger`). |
| `-o, --output` | Findings JSON (default `auth_results.json`), written incrementally and atomically. |
| `-w, --workers` | Threads (default `10`). |
| `-t, --timeout` | Per-request timeout in seconds (default `10`). |
| `-m, --method` | Baseline HTTP method: `GET` (default), `HEAD`, `POST`. |
| `-p, --paths` | Paths appended to each target; also feeds proxy auto mode. |
| `--header` | Extra `Key: Value` header (repeatable). |
| `--no-verify-ssl` | Disable TLS verification. |
| `--fail-only` | Console: print only failures/findings. |
| `--tqdm` | Progress bar instead of the per-line log. |
| `--allow-trivial-bodies` | Do not filter health-check bodies as false positives. |
| `--ignore-body-value V` | Add a trivial body value to the filter (repeatable). |
| `--full` | Run all checks (see **Checks**). |
| `--exclude` | Comma-separated check names to skip: `jwt`, `kid`, `nextjs`, `proxy`. |
| `--swagger` | Treat `-f` as Swagger UI URLs and discover endpoints (see **Swagger mode**). |
| `--skip-baseline` | Skip phase 1 and go straight to proxy-bypass. |

**JWT tuning:** `--jwt-secret`, `--jwt-payload FILE`, `--jwt-azure-b2c`,
`--jwt-claim K=V` (repeatable), `--jwt-rsa-pubkey FILE|URL`,
`--jwt-identities FILE`, `--jwt-header-name`, `--jwt-cookie-name`.
**Proxy tuning:** `--proxy-bypass-map FILE`.

---

## Swagger mode

With `--swagger`, `-f` is a list of Swagger UI URLs — plain, or nuclei output
(the first `http(s)` token on each line is used). For each source the tool fetches
the spec (`swagger.json` / `openapi.json` / `swagger-ui-init.js`), extracts the
GET endpoints, expands `{id}`-style params into `1/2/3/me/current/admin`, and runs
the same checks against them. `-p/--paths` is ignored in this mode.

```bash
nuclei -l alive.txt -t swagger.yaml -o swagger_endpoints.txt -rl 1000 -c 100
python3 auth_checker.py -f swagger_endpoints.txt --swagger --full -o results.json
```

---

## Examples

```bash
# Baseline, 50 threads, save to file
python3 auth_checker.py -f targets.txt -w 50 -o results.json

# JWT forgery with a custom secret + Azure B2C payload
python3 auth_checker.py -f targets.txt --jwt-test --jwt-secret s3cr3t --jwt-azure-b2c

# RS256 -> HS256 key confusion with a public key
python3 auth_checker.py -f targets.txt --jwt-test --jwt-rsa-pubkey pubkey.pem

# Impersonate specific users
python3 auth_checker.py -f targets.txt --jwt-test --jwt-identities victims.json

# Only the kid signature-bypass test
python3 auth_checker.py -f targets.txt --jwt-kid-test

# Next.js CVE with a session cookie
python3 auth_checker.py -f targets.txt --check-nextjs-cve --header 'Cookie: session=abc'

# Proxy bypass: explicit map / auto from protected paths
python3 auth_checker.py -f targets.txt --check-proxy-bypass --proxy-bypass-map map.txt
python3 auth_checker.py -f targets.txt -p protected_paths.txt --check-proxy-bypass

# Full sweep, excluding the noisy proxy auto-scan
python3 auth_checker.py -f targets.txt --full --exclude proxy --tqdm -o results.json

# Swagger discovery + all checks
python3 auth_checker.py -f swagger_endpoints.txt --swagger --full -o results.json
```

Input-file formats:

- `--proxy-bypass-map`: `direct_URL => bypass_template` per line; the template must contain `{payload}`.
- `--jwt-identities`: JSON array, e.g. `[{"sub":"...","emails":["u@corp.com"]}, ...]`.

---

## Output

Only **findings** are written — cleanly protected and 404/error results stay in
the console log. Writes are incremental and atomic, so the file is always valid
JSON and can be tailed during a run.

- Without `--check-proxy-bypass`: a flat list of finding objects.
- With it: `{ "results": [...], "proxy_bypass": [...] }` (each proxy entry carries `severity` and `sensitive_indicators`).

An endpoint open **without any token** is recorded once as `no_auth_required`; the
JWT and `kid` batteries are skipped for it, so you don't get many entries that
differ only by token `kind`.

Exit code: `0` if there were no baseline failures, else `2` (a protected endpoint
counts as a baseline "failure" — the secure outcome).

---

## Verdicts

- **JWT** — `no_auth_required` · `confirmed_vulnerable` (forged token accepted) · `signature_not_validated` (garbage accepted) · `protected`
- **kid** — `confirmed_full_bypass` · `signature_check_skipped_with_kid` · `differential_behavior_review` · `protected`
- **Next.js CVE** — `confirmed_bypass` · `protected` · `not_applicable`
- **Proxy** — `confirmed_bypass` (+ severity) · `protected` · `not_applicable`
