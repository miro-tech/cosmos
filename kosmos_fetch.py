#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Kosmos VPN 1.3.4 — PyCryptodome extractor

pip install requests pycryptodome

Run:
    python kosmos_fetch.py
"""

import base64
import json
import random
import re
import string
import sys
import time
import uuid

from pathlib import Path
from urllib.parse import urlencode

import requests

from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305


# ============================================================
# SETTINGS
# ============================================================

API = "https://kosmos.tunnelguard.ru/api/"
MAIL_API = "https://api.mail.tm"

UA = "SpaceVPN/Android/1.3.4"

MAIL_TIMEOUT = 180
MAIL_INTERVAL = 4

OUTPUT_CONFIG = "configs_plain.json"
OUTPUT_LINKS = "cosmos_links.txt"
OUTPUT_INFO = "user_info.json"


# ============================================================
# DEVICE IDENTITY
# ============================================================

def generate_device():

    models = [
        "SM-S928B",
        "SM-S921B",
        "SM-A556B",
        "SM-A536B",
        "SM-A546B",
        "Pixel 8",
        "Pixel 9",
        "Pixel 9 Pro",
        "2201117TG",
        "2312DRA50G",
        "RMX3709",
        "CPH2581",
    ]

    versions = ["12", "13", "14", "15", "16"]

    return (
        str(uuid.uuid4()),
        random.choice(models),
        random.choice(versions),
        "Android-" + "".join(
            random.choices(
                string.ascii_uppercase + string.digits,
                k=8,
            )
        ),
    )


DEVICE_TOKEN, MODEL, ANDROID_VER, DEVICE_NAME = generate_device()


# ============================================================
# STATIC KEY
# ============================================================

TABLE_A = bytes.fromhex(
    "dc46de8310df22c269a9633495c7e5b7"
    "c7d81152bb478bf83dc2903ec7d71ba1"
)

TABLE_B = bytes.fromhex(
    "f2bbf2add8ad90280103f81519608252"
    "f34b005e1d7604036aa2901c2f1bc2e2"
)

STATIC_PRIV = bytes(
    a ^ b for a, b in zip(TABLE_A, TABLE_B)
)


# ============================================================
# HTTP SESSIONS
# ============================================================

session = requests.Session()
session.headers.update({
    "User-Agent": UA,
    "Accept": "application/json",
})

mail_session = requests.Session()
mail_session.headers.update({
    "Accept": "application/json",
})


# ============================================================
# HELPERS
# ============================================================

def rnd_name(length=14):

    chars = string.ascii_lowercase + string.digits

    return "".join(
        random.choice(chars)
        for _ in range(length)
    )


def get_json(response):

    response.raise_for_status()

    try:
        return response.json()
    except Exception:
        raise RuntimeError(
            "Invalid JSON response: "
            + response.text[:1000]
        )


def save_json(filename, data):

    Path(filename).write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


# ============================================================
# MAIL.TM
# ============================================================

def mailtm_create():

    print("[*] Getting mail.tm domains...")

    response = mail_session.get(
        MAIL_API + "/domains",
        timeout=30,
    )

    data = get_json(response)

    if isinstance(data, list):
        domains = data

    elif isinstance(data, dict):
        domains = data.get("hydra:member", [])

    else:
        raise RuntimeError(
            "Unexpected domains response: "
            + repr(data)[:1000]
        )

    active_domains = [
        item["domain"]
        for item in domains
        if isinstance(item, dict)
        and item.get("domain")
        and item.get("isActive", True)
    ]

    if not active_domains:
        raise RuntimeError("No active mail.tm domains")

    email = rnd_name() + "@" + active_domains[0]
    password = rnd_name(20)

    print("[*] Creating mailbox:", email)

    response = mail_session.post(
        MAIL_API + "/accounts",
        json={
            "address": email,
            "password": password,
        },
        timeout=30,
    )

    get_json(response)

    print("[+] Mailbox created")

    response = mail_session.post(
        MAIL_API + "/token",
        json={
            "address": email,
            "password": password,
        },
        timeout=30,
    )

    token_data = get_json(response)

    print("[+] mail.tm authorization successful")

    return email, token_data["token"]


def mailtm_wait_code(token):

    print("[*] Waiting for verification email...")

    headers = {
        "Authorization": "Bearer " + token,
    }

    deadline = time.time() + MAIL_TIMEOUT
    processed = set()

    while time.time() < deadline:

        response = mail_session.get(
            MAIL_API + "/messages",
            headers=headers,
            timeout=30,
        )

        messages = get_json(response)

        if isinstance(messages, list):
            message_list = messages

        elif isinstance(messages, dict):
            message_list = messages.get(
                "hydra:member",
                [],
            )

        else:
            message_list = []

        for message in message_list:

            message_id = message.get("id")

            if not message_id or message_id in processed:
                continue

            processed.add(message_id)

            response = mail_session.get(
                MAIL_API + "/messages/" + message_id,
                headers=headers,
                timeout=30,
            )

            body = get_json(response)

            parts = []

            for field in ("subject", "text", "intro"):
                value = body.get(field)

                if isinstance(value, str):
                    parts.append(value)

            html = body.get("html", [])

            if isinstance(html, list):
                parts.extend(
                    item for item in html
                    if isinstance(item, str)
                )

            elif isinstance(html, str):
                parts.append(html)

            content = "\n".join(parts)
            content = re.sub(r"<[^>]+>", " ", content)
            content = content.replace("&nbsp;", " ")

            match = re.search(
                r"(?<!\d)(\d{4,6})(?!\d)",
                content,
            )

            if match:
                print("[+] Verification code received")
                return match.group(1)

        print("[*] No code yet...")
        time.sleep(MAIL_INTERVAL)

    raise TimeoutError(
        "Verification code was not received"
    )


# ============================================================
# KOSMOS API
# ============================================================

def api(path, payload=None, auth=None):

    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if auth:
        headers["Authorization"] = auth

    url = API + path.lstrip("/")

    if payload is not None:
        response = session.post(
            url,
            json=payload,
            headers=headers,
            timeout=60,
        )
    else:
        response = session.get(
            url,
            headers=headers,
            timeout=60,
        )

    if not response.ok:
        raise RuntimeError(
            f"Kosmos HTTP {response.status_code}\n"
            f"URL: {url}\n"
            f"Response: {response.text[:3000]}"
        )

    try:
        return response.json()
    except Exception:
        raise RuntimeError(
            "Invalid Kosmos JSON response: "
            + response.text[:1000]
        )


# ============================================================
# LOGIN
# ============================================================

def login(email, mail_token):

    print("[*] Kosmos auth/check_email...")

    check = api(
        "auth/check_email",
        {
            "email": email,
        },
    )

    print("[+] Email check response:")
    print(json.dumps(check, ensure_ascii=False))

    code = mailtm_wait_code(mail_token)

    print("[*] Submitting verification code...")

    # ВАЖНО:
    # По формату запроса из декомпилированного APK
    # токен передаётся в JSON как "Authorization".
    payload = {
        "email": email,
        "code": code,
        "device_os": "Android",
        "ver_os": ANDROID_VER,
        "Authorization": DEVICE_TOKEN,
        "uname": DEVICE_NAME,
        "model": MODEL,
    }

    response = api(
        "auth/send_code",
        payload,
    )

    print("[+] Kosmos login response:")
    print(
        json.dumps(
            response,
            ensure_ascii=False,
            indent=2,
        )
    )

    return response


def fetch_userinfo():

    print("[*] Fetching user/info...")

    # Здесь Authorization — HTTP-заголовок.
    return api(
        "user/info",
        auth=DEVICE_TOKEN,
    )


# ============================================================
# X25519
# ============================================================

def import_x25519_public(raw):

    if len(raw) != 32:
        raise ValueError(
            "X25519 public key must be 32 bytes"
        )

    der_prefix = bytes.fromhex(
        "302a300506032b656e032100"
    )

    return ECC.import_key(
        der_prefix + raw
    )


# ============================================================
# KVPNENC1 DECRYPTION
# ============================================================

def decrypt_bundle(value):

    if isinstance(value, bytes):
        data = value

    elif value.startswith("kvpnenc1:"):
        data = base64.b64decode(
            value.split(":", 1)[1],
            validate=True,
        )

    else:
        data = base64.b64decode(
            value,
            validate=True,
        )

    if len(data) < 70:
        raise ValueError(
            "KVPNENC1 envelope is too short"
        )

    if data[:8] != b"KVPNENC1":
        raise ValueError(
            "Invalid KVPNENC1 magic"
        )

    version = data[8:10]
    eph_raw = data[10:42]
    nonce = data[42:54]
    ciphertext_tag = data[54:]

    print("[*] Envelope version:", version.hex())

    static_priv = ECC.construct(
        curve="Curve25519",
        seed=STATIC_PRIV,
    )

    eph_pub = import_x25519_public(eph_raw)

    print("[*] X25519 key agreement...")

    shared_secret = key_agreement(
        static_priv=static_priv,
        eph_pub=eph_pub,
        kdf=lambda x: x,
    )

    print("[*] HKDF-SHA256...")

    key = HKDF(
        master=shared_secret,
        key_len=32,
        salt=eph_raw,
        hashmod=SHA256,
        context=b"kvpn-config-v1" + version,
    )

    ciphertext = ciphertext_tag[:-16]
    tag = ciphertext_tag[-16:]

    cipher = ChaCha20_Poly1305.new(
        key=key,
        nonce=nonce,
    )

    cipher.update(data[:42])

    plaintext = cipher.decrypt_and_verify(
        ciphertext,
        tag,
    )

    print("[+] Bundle decrypted successfully")

    return json.loads(plaintext)


# ============================================================
# BUNDLE EXTRACTION
# ============================================================

def extract_bundle(info):

    result = info.get("result", {})
    servers = result.get("servers", {})

    if isinstance(servers, dict):
        bundle = servers.get("bundle")
    else:
        bundle = servers

    if not bundle:
        raise RuntimeError("servers.bundle not found")

    print("[*] Decoding servers.bundle...")

    decoded = base64.b64decode(
        bundle,
        validate=True,
    )

    arr = json.loads(decoded)

    if not isinstance(arr, list) or not arr:
        raise ValueError(
            "Invalid servers.bundle JSON"
        )

    print("[+] Bundle items:", len(arr))

    return arr


# ============================================================
# VLESS LINKS
# ============================================================

def resolve_ip(host):
    """Resolve hostname to IPv4; fall back to host on failure."""
    try:
        import socket
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception as e:
        print("[!] DNS resolve failed for %s: %s" % (host, e))
    return host


def vless_links(cfg):

    links = []

    for outbound in cfg.get("outbounds", []):

        if outbound.get("type") != "vless":
            continue

        host = outbound["server"]
        port = outbound.get("server_port", 443)
        user_uuid = outbound.get("uuid", "")

        tls = outbound.get("tls", {}) or {}
        reality = tls.get("reality", {}) or {}

        public_key = reality.get("public_key", "")
        short_id = reality.get("short_id", "")
        sni = tls.get("server_name", host)

        flow = outbound.get("flow", "")

        transport = outbound.get(
            "transport", {}
        ) or {}

        params = {
            "encryption": "none",
            "security": "reality",
            "sni": sni,
            "fp": (tls.get("utls") or {}).get("fingerprint") or "firefox",
            "pbk": public_key,
            "sid": short_id,
        }

        if transport.get("type") == "grpc":

            params["type"] = "grpc"
            params["serviceName"] = transport.get(
                "service_name", ""
            )
            params["mode"] = "gun"

        else:

            params["type"] = "tcp"

            if flow:
                params["flow"] = flow

        tag = outbound.get("tag", "srv").replace(" ", "")
        if "cosmos" not in tag.lower():
            tag = "cosmos-" + tag

        ip = resolve_ip(host)
        print("[*] %s -> %s" % (host, ip))

        links.append(
            "vless://%s@%s:%s?%s#%s"
            % (
                user_uuid,
                ip,
                port,
                urlencode(params),
                tag,
            )
        )

    return links


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 55)
    print("Kosmos VPN 1.3.4 — PyCryptodome extractor")
    print("=" * 55)

    print("[+] Generated device identity")
    print("[+] Model:", MODEL)
    print("[+] Android:", ANDROID_VER)
    print("[+] Device:", DEVICE_NAME)

    email, mail_token = mailtm_create()

    print("[+] Temporary email:", email)

    login(email, mail_token)

    info = fetch_userinfo()

    save_json(OUTPUT_INFO, info)

    print("[+] user_info.json saved")

    arr = extract_bundle(info)

    cfg = decrypt_bundle(arr[0])

    if not isinstance(cfg, dict):
        raise ValueError(
            "Decrypted config is not a JSON object"
        )

    # Сохраняем расшифрованный конфиг без изменения
    # его структуры и содержимого.

    save_json(OUTPUT_CONFIG, cfg)

    print("[+] Original config saved:", OUTPUT_CONFIG)

    links = vless_links(cfg)

    Path(OUTPUT_LINKS).write_text(
        "\n".join(links),
        encoding="utf-8",
    )

    print()
    print("=" * 55)
    print("[+] Original outbounds:", len(cfg.get("outbounds", [])))
    print("[+] VLESS links:", len(links))
    print("[+] Config:", OUTPUT_CONFIG)
    print("[+] Links:", OUTPUT_LINKS)
    print("=" * 55)

    for link in links:
        print(link)


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)

    except Exception as error:
        print(
            "\n[ERROR]",
            type(error).__name__ + ":",
            str(error),
        )
        sys.exit(1)
        
