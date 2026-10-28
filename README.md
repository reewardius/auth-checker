# auth_checker

A concurrent authorization-bypass checker for HTTP/JSON endpoints. It runs a
baseline reachability check on every target and, on request, a set of
authorization-bypass tests (JWT forgery, JWT `kid` signature bypass, the Next.js
`CVE-2025-29927` middleware bypass, and proxy-path traversal bypass). Findings
are printed to the console with ready-to-paste `curl` PoCs and written
incrementally to a JSON file.

> **Authorized use only.** Run this only against systems you own or have explicit
> written permission to test. The bypass tests send forged tokens and traversal
> payloads and are intended for your own targets in a lab or an authorized
> engagement.

---

## Examples

```bash
# Baseline only, 20 threads, custom timeout
python3 auth_checker.py -f targets.txt -w 20 -t 15

# JWT forgery with a custom secret and Azure B2C payload
python3 auth_checker.py -f targets.txt --jwt-test --jwt-secret s3cr3t --jwt-azure-b2c

# Only the kid signature-bypass test
python3 auth_checker.py -f targets.txt --jwt-kid-test

# Next.js CVE check with an auth header
python3 auth_checker.py -f targets.txt --check-nextjs-cve --header 'Cookie: session=abc'

# Impersonation: forge sessions for specific users
python3 auth_checker.py -f targets.txt --jwt-test --jwt-identities victims.json

# Proxy-path bypass from an explicit map
python3 auth_checker.py -f targets.txt --check-proxy-bypass --proxy-bypass-map map.txt

# Full sweep, progress bar, results to file
python3 auth_checker.py -f targets.txt -p paths.txt --full --tqdm -o results.json

# Swagger mode: discover endpoints from Swagger/OpenAPI specs, then check them
python3 auth_checker.py -f swagger_endpoints.txt --swagger -o results.json
python3 auth_checker.py -f swagger_endpoints.txt --swagger --full -o results.json
```

---

## Requirements

- Python 3.9+
- [`requests`](https://pypi.org/project/requests/) (required)
- [`tqdm`](https://pypi.org/project/tqdm/) (optional, only for the `--tqdm` progress bar)

```bash
pip install requests
pip install tqdm   # optional
```

---

## Quick start

Create a targets file, one URL per line (empty lines and lines starting with `#`
are ignored; a line without a scheme defaults to `http://`):

```text
# targets.txt
https://api.example.com/v1/users
https://api.example.com/v1/orders
```

Run the baseline check:

```bash
python3 auth_checker.py -f targets.txt
```

Run everything at once:

```bash
python3 auth_checker.py -f targets.txt --full -p paths.txt -o results.json
```

---

## What it checks

### 1. Baseline (always runs unless `--skip-baseline`)

For each target URL a response counts as **OK** only if **all** of these hold:

- HTTP status is `200`
- `Content-Type` is `application/json` or `text/plain`
- body is non-empty (not 0 bytes)
- body is not a trivial health-check (`OK`, `HEALTHY`, `PONG`, `{"status":"ok"}`, …)

Trivial health-check bodies are filtered as false positives by default. Disable
that with `--allow-trivial-bodies`, or add your own trivial values with
`--ignore-body-value VALUE` (repeatable).

A baseline-OK endpoint that requires no token is itself a finding
(`no_auth_required`).

### 2. JWT forgery — `--jwt-test`

Sends a battery of forged tokens, each delivered both as a `Bearer` header and as
a cookie:

- `hs256_default_secret` — HS256 signed with a weak secret (`--jwt-secret`, default `secret`)
- `alg_none` / `alg_None` / `alg_NONE` — `alg:none` tokens (case variants)
- `alg_none_empty_payload` — `alg:none` with an empty payload
- `rs256_to_hs256_confusion` — RS256→HS256 key-confusion (only if `--jwt-rsa-pubkey` is given)
- `garbage_signature` — **negative control**: valid structure, random signature

The negative control is what makes the verdict trustworthy: if even a garbage
signature is accepted, the server is not checking signatures at all (as opposed
to merely using a weak secret).

### 3. JWT `kid` signature bypass — `--jwt-kid-test`

A **differential** test for servers that skip signature validation when a `kid`
header is present. It sends the same garbage-signed token **without** `kid` and
**with** `kid` (for `alg` = HS256 / RS256 / none) and compares the responses.

This matters because such a bug often does **not** produce a `200` — the server
may still return `401`, but with a *different* error (e.g. `"signature key not
found"` without `kid` vs `"issuer is invalid"` with `kid`). The differential
logic catches exactly that transition from the signature stage to the claim
stage. See the verdict table below.

### 4. Next.js middleware bypass (CVE-2025-29927) — `--check-nextjs-cve`

Sends the `x-middleware-subrequest` header with known payloads. If an endpoint
that is otherwise not reachable starts returning real data, the middleware
(and any auth it implements) was bypassed. Affects Next.js `< 12.3.5`,
`< 13.5.9`, `< 14.2.25`, `< 15.2.3` (CVSS 9.1).

### 5. Proxy-path traversal bypass — `--check-proxy-bypass`

Tests whether a protected resource can be reached through an adjacent **public**
proxy path (e.g. `/api/swagger/…`) using encoded path traversal (`%2e%2e`, …),
when the authorizer is bound to the direct route rather than the backend.
Relevant for AWS API Gateway `{proxy+}`, Swagger proxies, and similar
reverse-proxy routes.

Two ways to supply pairs (you can use both together):

- **Manual map** (`--proxy-bypass-map FILE`) — one `direct_URL => bypass_template`
  per line; the template must contain `{payload}`:

  ```text
  https://host/dev/api/v1/items?x=1 => https://host/dev/api/swagger/{payload}v1/items?x=1
  ```

- **Auto mode** (`--paths FILE`) — for each target × protected path, the tool
  generates traversal candidates through a built-in list of common public
  prefixes (`swagger`, `api-docs`, `openapi`, `public`, `health`, `prod/api`, …).

Confirmed bypasses are assigned a **severity** from the leaked body:

| Severity | Meaning |
|----------|---------|
| `HIGH`   | credentials/secrets in the body (passwords, tokens, API keys, Luhn-valid card numbers, IBAN, JWT-like strings) |
| `MEDIUM` | PII-like fields (email, phone, address, name, …), or confirmed but unknown/binary body |
| `LOW`    | bypass technically confirmed, but no clearly sensitive data found |

---

## Swagger mode (`--swagger`)

With `--swagger`, the `-f` file is treated as a list of **Swagger UI URLs**
instead of target endpoints. For each source the tool:

1. tries common spec locations (`/swagger/v1/swagger.json`, `/openapi.json`,
   `/swagger/swagger-ui-init.js`, …), including the JS-embedded `swaggerDoc`;
2. parses the OpenAPI/Swagger spec and extracts every endpoint path;
3. keeps the **GET** endpoints and expands `{id}`-style path params into probe
   values (`1`, `2`, `3`, `me`, `current`, `admin`);
4. runs the **same checks** as in normal mode (baseline, and whatever of
   `--jwt-test` / `--jwt-kid-test` / `--check-nextjs-cve` you add) against the
   discovered URLs, writing findings to the same JSON output.

The input file accepts both plain-URL lines and **nuclei-style** output lines —
the first `http(s)` token on each line is used, so nuclei output can be fed
directly. `-p/--paths` is ignored in this mode (paths come from the spec).

Typical workflow:

```bash
# 1) discover Swagger UIs with nuclei
nuclei -l alive_http_services_advanced.txt -t swagger.yaml \
       -o swagger_endpoints.txt -rl 1000 -c 100

# 2) extract endpoints from the specs and run the checks
python3 auth_checker.py -f swagger_endpoints.txt --swagger -o results.json

# with all bypass checks too
python3 auth_checker.py -f swagger_endpoints.txt --swagger --full -o results.json
```

---

## `--full`

Enables `--jwt-test`, `--jwt-kid-test`, and `--check-nextjs-cve` at once, plus
`--check-proxy-bypass` **if** a `--proxy-bypass-map` or `--paths` is provided.
Under `--full` the JWT test runs **both** built-in profiles (`generic_admin` and
`azure_b2c`) unless you set your own `--jwt-payload` / `--jwt-azure-b2c` /
`--jwt-claim`.

```bash
# full sweep with auto proxy-bypass from a protected-paths file
python3 auth_checker.py -f targets.txt -p paths.txt --full -o results.json

# full sweep with an explicit proxy map
python3 auth_checker.py -f targets.txt --full --proxy-bypass-map map.txt
```

---

## Excluding checks (`--exclude`)

`--exclude` takes a comma-separated list of check names and turns those checks
off. It is applied **after** `--full` and the individual flags, so the usual
pattern is "enable everything, then drop a few":

```bash
# everything except the kid test and the (noisy) proxy auto-scan
python3 auth_checker.py -f targets.txt --full --exclude kid,proxy

# swagger discovery, all checks except Next.js CVE
python3 auth_checker.py -f swagger_endpoints.txt --swagger --full --exclude nextjs
```

| Name | Check it disables | Equivalent flag | Aliases |
|------|-------------------|-----------------|---------|
| `jwt` | JWT forgery (weak secret, `alg=none`, RS256→HS256) | `--jwt-test` | `jwt-test` |
| `kid` | JWT `kid` signature bypass (differential) | `--jwt-kid-test` | `kid-test`, `jwt-kid`, `jwt-kid-test` |
| `nextjs` | Next.js middleware bypass (CVE-2025-29927) | `--check-nextjs-cve` | `nextjs-cve`, `cve`, `cve-2025-29927` |
| `proxy` | Proxy-path traversal bypass | `--check-proxy-bypass` | `proxy-bypass` |

Notes:

- Names are case-insensitive; unknown names are warned about on stderr and ignored.
- The **baseline** reachability check is not excludable here — it always runs (and
  other checks depend on its result). To skip it entirely, use `--skip-baseline`.
- Excluding a check also suppresses its "requires ..." validation, so e.g.
  `--check-proxy-bypass --exclude proxy` will not error about a missing map.

---

## Options

| Flag | Description |
|------|-------------|
| `-f, --file` | **Required.** Targets file (one URL/domain per line). |
| `-p, --paths` | Paths file; each path is appended to every target (and feeds auto proxy-bypass). |
| `--swagger` | Treat `-f` as a list of Swagger UI URLs; discover endpoints from the specs and check them (see "Swagger mode" below). |
| `-t, --timeout` | Per-request timeout in seconds (default `10`). |
| `-w, --workers` | Parallel threads (default `10`). |
| `-m, --method` | HTTP method for the baseline: `GET` (default), `HEAD`, `POST`. |
| `-o, --output` | Findings JSON path (default `auth_results.json`), written incrementally. |
| `--no-verify-ssl` | Disable TLS certificate verification. |
| `--header` | Extra `Key: Value` header (repeatable). |
| `--fail-only` | Print only failed/finding lines to the console. |
| `--tqdm` | Show a progress bar instead of the per-URL log (needs `tqdm`). |
| `--allow-trivial-bodies` | Do not filter health-check bodies as false positives. |
| `--ignore-body-value` | Extra trivial body value to filter (repeatable). |
| `--check-nextjs-cve` | Enable the CVE-2025-29927 check. |
| `--jwt-test` | Enable JWT forgery checks. |
| `--jwt-kid-test` | Enable the differential JWT `kid` signature-bypass check. |
| `--jwt-secret` | HS256 secret for the weak-secret token (default `secret`). |
| `--jwt-payload` | JSON file with custom token claims. |
| `--jwt-header-name` | Header for the Bearer variant (default `Authorization`). |
| `--jwt-cookie-name` | Cookie name for the cookie variant (default `access_token`). |
| `--jwt-azure-b2c` | Use an Azure AD B2C style payload as the default. |
| `--jwt-rsa-pubkey` | File or URL of a public RSA key (PEM) for RS256→HS256 confusion. |
| `--jwt-claim` | Override/add a single claim `KEY=VALUE` (repeatable; value parsed as JSON). |
| `--jwt-identities` | JSON file of identities to forge sessions for (impersonation testing). |
| `--check-proxy-bypass` | Enable proxy-path traversal bypass (needs `--proxy-bypass-map` and/or `--paths`). |
| `--proxy-bypass-map` | File of `direct_URL => bypass_template` pairs. |
| `--skip-baseline` | Skip phase 1 and go straight to proxy-bypass. |
| `--full` | Run all checks at once (see above). |
| `--exclude` | Comma-separated checks to exclude from the scan (see "Excluding checks"). |

---

## Verdict reference

**JWT (`jwt_verdict`)**

| Verdict | Meaning |
|---------|---------|
| `no_auth_required` | Endpoint returns 200 without any token. |
| `confirmed_vulnerable` | Server validates signatures but accepted a forged token (weak secret / `alg=none`). |
| `signature_not_validated` | Signature not checked at all — even the garbage control was accepted. |
| `protected` | All forged tokens rejected. |

**JWT kid (`kid_verdict`)**

| Verdict | Meaning |
|---------|---------|
| `confirmed_full_bypass` | A token with `kid` was fully accepted (200 + data). |
| `signature_check_skipped_with_kid` | Without `kid` the server rejected on signature/key; with `kid` it moved on to claim checks → signature not verified when `kid` is present. |
| `differential_behavior_review` | `kid` changes the response, but the stage can't be classified automatically — review the body. |
| `protected` | `kid` changes nothing. |

**Next.js CVE (`nextjs_cve_verdict`)**

| Verdict | Meaning |
|---------|---------|
| `confirmed_bypass` | `x-middleware-subrequest` returned real data on a closed endpoint. |
| `protected` | Bypass did not work. |
| `not_applicable` | Endpoint was already reachable without the bypass. |

**Proxy bypass (`verdict`)**

| Verdict | Meaning |
|---------|---------|
| `confirmed_bypass` | Direct access closed, but the proxy path returned data (see `severity`). |
| `protected` | Direct closed, all bypass variants rejected. |
| `not_applicable` | Direct access already open. |

---

## Output file

- Only **findings** are written — cleanly protected endpoints and
  404/network-error results stay in the console log only.
- Writes are **atomic** (temp file + `os.replace`) and **incremental**, so the
  file is always valid JSON and can be tailed while the run is in progress.
- Format depends on whether proxy-bypass is enabled:

Without `--check-proxy-bypass` — a flat list of finding objects:

```json
[
  { "url": "...", "ok": true, "jwt_verdict": "...", "kid_verdict": "...", "...": "..." }
]
```

With `--check-proxy-bypass` — an object with two keys:

```json
{
  "results": [ { "url": "...", "...": "..." } ],
  "proxy_bypass": [
    {
      "direct_url": "...",
      "template": "...",
      "verdict": "confirmed_bypass",
      "severity": "HIGH",
      "sensitive_indicators": ["key:password"],
      "checks": [ { "payload": "...", "curl_poc": "...", "...": "..." } ]
    }
  ]
}
```

Each finding keeps only the accepted/meaningful attempts (real PoCs), not the
rejected negative controls.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No baseline failures. |
| `2` | At least one baseline target failed (note: a protected endpoint is a "fail" for the baseline, which is the expected/secure outcome). |
