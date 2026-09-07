# auth_checker.py

A multithreaded authorization-testing tool for **authorized penetration testing** of your own APIs. It checks whether protected endpoints are actually protected, and — if `--jwt-test` / `--check-nextjs-cve` / `--check-proxy-bypass` are enabled — tries several known bypass techniques against them.

> ⚠️ **Use only against targets you own or are explicitly authorized to test.** This tool sends forged JWTs, CVE exploitation payloads, and path-traversal requests. Running it against systems without authorization may be illegal.

## What it checks

| Check | Flag | What it does |
|---|---|---|
| Baseline | *(always runs)* | Requests each target/path without a token; flags `200 + JSON/text + non-empty, non-trivial body` as unauthenticated exposure |
| JWT bypass | `--jwt-test` | Weak HS256 secret, `alg=none` (multiple case variants), RS256→HS256 key confusion, negative control (garbage signature) to filter false positives |
| Next.js middleware bypass | `--check-nextjs-cve` | [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) (CVSS 9.1) — `x-middleware-subrequest` header bypass, Next.js < 12.3.5 / < 13.5.9 / < 14.2.25 / < 15.2.3 |
| Proxy-path traversal | `--check-proxy-bypass` | Encoded `../` traversal through a sibling public route (e.g. `/api/swagger/`) to reach a protected resource without triggering its authorizer — common AWS API Gateway `{proxy+}` misconfiguration |

Everything runs in parallel threads, results are streamed to a JSON file as they're found (not only at the end), and DNS lookups are cached so an unresolvable host doesn't stall every single request against it.

## Requirements

```bash
pip install requests
pip install tqdm   # optional, only needed for --tqdm
```

## Quick start

```bash
# Just check if targets are reachable without auth
python3 auth_checker.py -f targets.txt

# Run every available check
python3 auth_checker.py -f targets.txt -p paths.txt --full -o results.json
```

`targets.txt` — one base URL per line:
```
https://api.example.com/dev
https://8u1jbl6oe0.execute-api.eu-central-1.amazonaws.com/prod
```

`paths.txt` (optional, used with `-p`) — one path per line, combined with every target:
```
/api/v1/users
/api/v1/admin
/api/v1/orders
```

## Output

Findings are written to `-o` / `--output` (default: `auth_results.json`), **incrementally** — the file is valid JSON at every point during the run, so you can `cat`/`jq` it mid-scan. Only confirmed findings go in the file (open endpoints, confirmed JWT/CVE/proxy bypasses) — endpoints that were correctly protected are **not** written to disk, only shown in the console log.

```json
{
  "results": [
    {
      "url": "https://api.example.com/dev/api/v1/users",
      "ok": true,
      "status_code": 200,
      "jwt_verdict": "confirmed_vulnerable",
      "jwt_checks": [ { "kind": "generic_admin:hs256_default_secret", "delivery": "bearer", "accepted": true, "curl_poc": "curl -i -H 'Authorization: Bearer eyJ...' '...'" } ],
      "nextjs_cve_verdict": null
    }
  ],
  "proxy_bypass": [
    {
      "direct_url": "https://api.example.com/dev/api/v1/users",
      "template": "https://api.example.com/dev/api/swagger/{payload}v1/users",
      "verdict": "confirmed_bypass",
      "severity": "LOW",
      "sensitive_indicators": [],
      "checks": [ { "payload": "%2e%2e/", "status_code": 200, "curl_poc": "curl -skL --path-as-is '...'" } ]
    }
  ]
}
```

`proxy_bypass` entries include a heuristic **severity** (`LOW` / `MEDIUM` / `HIGH`) based on whether the leaked response body contains PII/credential-like fields (see `sensitive_indicators`).

## Usage examples

### 1. Baseline only — is anything open without a token?

```bash
python3 auth_checker.py -f targets.txt -p paths.txt
```

### 2. JWT bypass testing

```bash
python3 auth_checker.py -f targets.txt -p paths.txt --jwt-test
```

Tries, per endpoint: weak-secret HS256, `alg=none` (several casings), empty-payload `alg=none`, and a garbage-signature negative control — as both a `Bearer` header and a cookie.

Custom secret / claims:
```bash
python3 auth_checker.py -f targets.txt --jwt-test --jwt-secret 'my-guessed-secret'
python3 auth_checker.py -f targets.txt --jwt-test --jwt-claim role=admin --jwt-claim tenant_id=1
```

Azure AD B2C-style token + RS256→HS256 key confusion:
```bash
python3 auth_checker.py -f targets.txt --jwt-test --jwt-azure-b2c \
  --jwt-rsa-pubkey https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
```

Forge sessions for specific users (`identities.json`):
```json
[
  { "sub": "user-123", "oid": "aaaa-bbbb", "emails": ["victim@corp.com"], "name": "Victim User" },
  { "sub": "admin-1",  "oid": "cccc-dddd", "emails": ["admin@corp.com"],  "name": "Admin User" }
]
```
```bash
python3 auth_checker.py -f targets.txt --jwt-test --jwt-identities identities.json
```

### 3. CVE-2025-29927 (Next.js middleware bypass)

```bash
python3 auth_checker.py -f targets.txt --check-nextjs-cve
```

### 4. Proxy-path traversal bypass

**Auto mode** — no manual mapping needed, just give it paths. The script tries 18 common public-prefix patterns (`api/swagger`, `docs`, `health`, `prod/api`, `dev/api`, etc.) × 10 traversal-payload variants (including a plain, non-obfuscated substitution) for every target × path combination:

```bash
python3 auth_checker.py -f targets.txt -p paths.txt --check-proxy-bypass -o results.json
```

**Manual mode** — when you already know the exact bypass route:

`proxy_map.txt`:
```
https://host/dev/api/v1/users => https://host/dev/api/swagger/{payload}v1/users
https://host/dev/admin/orders => https://host/dev/internal-docs/{payload}admin/orders
```
```bash
python3 auth_checker.py -f targets.txt --check-proxy-bypass --proxy-bypass-map proxy_map.txt -o results.json
```

Run **only** the proxy-bypass check, skipping the baseline pass entirely:
```bash
python3 auth_checker.py -f targets.txt --check-proxy-bypass --proxy-bypass-map proxy_map.txt --skip-baseline
```

### 5. Everything at once

```bash
python3 auth_checker.py -f targets.txt -p paths.txt --full -o results.json
```

`--full` enables `--jwt-test` (both a generic-admin and an Azure B2C profile, unless you already passed `--jwt-payload`/`--jwt-azure-b2c`/`--jwt-claim`), `--check-nextjs-cve`, and `--check-proxy-bypass` (auto mode if `-p` is given, plus your `--proxy-bypass-map` if you also passed one).

### 6. Progress bar instead of a verbose log

```bash
pip install tqdm
python3 auth_checker.py -f targets.txt -p paths.txt --full --tqdm -o results.json
```

Console output shrinks to progress bars; the JSON findings file and end-of-run summaries are unaffected.

### 7. Tuning requests

```bash
python3 auth_checker.py -f targets.txt -p paths.txt --full \
  -t 5 -w 30 \
  --no-verify-ssl \
  --header 'X-Api-Key: test123' \
  --fail-only
```

- `-t/--timeout` — per-request timeout in seconds (default `10`)
- `-w/--workers` — thread pool size (default `10`)
- `-m/--method` — `GET` / `HEAD` / `POST` (default `GET`)
- `--no-verify-ssl` — skip TLS certificate validation (self-signed/internal certs)
- `--header 'Key: Value'` — add a header to every request (repeatable)
- `--fail-only` — only print non-2xx / failed checks to the console

### 8. Reducing false positives

Health-check-style bodies (`{"status":"ok"}`, `OK`, `pong`, ...) are filtered out by default so they don't get counted as a real bypass. To disable that filter, or add your own trivial values:

```bash
python3 auth_checker.py -f targets.txt --check-proxy-bypass --allow-trivial-bodies
python3 auth_checker.py -f targets.txt --check-proxy-bypass --ignore-body-value alive --ignore-body-value nominal
```

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| `confirmed_vulnerable` | Server validates JWTs, but accepted a forged one (weak secret / `alg=none`) |
| `signature_not_validated` | Signature isn't checked at all — even a garbage signature was accepted |
| `no_auth_required` | Endpoint returns `200` with no token whatsoever |
| `confirmed_bypass` (CVE / proxy) | The bypass technique worked |
| `protected` | All bypass attempts were correctly rejected |
| `not_applicable` | The endpoint was already open at baseline — the bypass test wasn't meaningful |

## Notes

- All probe requests use `allow_redirects=False` — a `3xx` never counts as a successful bypass, and the tool won't chase redirects into unrelated internal infrastructure.
- Unresolvable hostnames are cached after the first DNS failure, so one bad host doesn't multiply into hundreds of timeouts across every JWT/CVE/proxy-bypass variant.
- `--proxy-bypass-map` templates support any structure, not just the auto-generated ones — the only requirement is a literal `{payload}` placeholder.
