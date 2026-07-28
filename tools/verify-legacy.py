#!/usr/bin/env python3
"""Interactively trace Cryptiki v1/v2 recovery against the legacy SQL dump.

This tool is intentionally local-first. It reads the legacy dump, derives the
same v1/v2 values as the old browser, and reports stage-by-stage results
without printing passwords, hashes, ciphertext, or plaintext. With --url it
also fetches the opaque recovery capsule from a Cryptiki deployment; the
request contains only the derived lookup ID.

The implementation uses only Python's standard library. A local Node.js
runtime and this repository are needed only for the optional capsule check,
because Cryptiki's existing vendored Argon2id implementation is JavaScript.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


V2_SALT = b"Cryptiki 2.0"
V2_ITERATIONS = 133700
MAX_CONTENT = 512 * 1024
CAPSULE_SALT = b"cryptiki.recovery.salt.v1\0"
CAPSULE_LOOKUP = b"cryptiki.recovery.lookup.v1"
CAPSULE_ENCRYPTION = b"cryptiki.recovery.encryption.v1"
CAPSULE_AAD_PREFIX = b"cryptiki.recovery.capsule.v1\0"


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def hex_digest(value: bytes) -> str:
    return value.hex()


def derive_legacy(format_number: int, page: str, password: str, recovery_code: str = "") -> tuple[bytes, bytes]:
    if recovery_code:
        try:
            keyhash = bytes.fromhex(recovery_code)
        except ValueError as exc:
            raise ValueError("recovery code is not hexadecimal") from exc
        if len(keyhash) != 32:
            raise ValueError("recovery code must be exactly 64 hexadecimal characters")
    elif format_number == 1:
        keyhash = sha256(page.encode("utf-8"))
    else:
        keyhash = hashlib.pbkdf2_hmac("sha256", page.encode("utf-8"), V2_SALT, V2_ITERATIONS, 32)

    if format_number == 1:
        passhash = sha256(password.encode("utf-8"))
    else:
        passhash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), keyhash, V2_ITERATIONS, 32)
    return keyhash, passhash


# AES-256 implementation, kept here so the verifier has no package dependency.
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def aes_round_keys(key: bytes) -> list[bytes]:
    if len(key) != 32:
        fail("internal AES key must be 32 bytes")
    words = [list(key[index:index + 4]) for index in range(0, 32, 4)]
    for index in range(8, 60):
        word = words[index - 1][:]
        if index % 8 == 0:
            word = word[1:] + word[:1]
            word = [SBOX[value] for value in word]
            word[0] ^= RCON[index // 8 - 1]
        elif index % 8 == 4:
            word = [SBOX[value] for value in word]
        words.append([words[index - 8][offset] ^ word[offset] for offset in range(4)])
    return [bytes(value for word in words[index:index + 4] for value in word) for index in range(0, 60, 4)]


def xtime(value: int) -> int:
    return ((value << 1) ^ (0x11B if value & 0x80 else 0)) & 0xFF


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        fail("internal AES block must be 16 bytes")
    round_keys = aes_round_keys(key)
    state = list(xor_bytes(block, round_keys[0]))
    for round_key in round_keys[1:-1]:
        state = [SBOX[value] for value in state]
        shifted = [0] * 16
        for row in range(4):
            for column in range(4):
                shifted[4 * column + row] = state[4 * ((column + row) % 4) + row]
        state = shifted
        for column in range(4):
            at = 4 * column
            a0, a1, a2, a3 = state[at:at + 4]
            b0, b1, b2, b3 = xtime(a0), xtime(a1), xtime(a2), xtime(a3)
            state[at:at + 4] = [b0 ^ (a1 ^ b1) ^ a2 ^ a3, a0 ^ b1 ^ (a2 ^ b2) ^ a3, a0 ^ a1 ^ b2 ^ (a3 ^ b3), (a0 ^ b0) ^ a1 ^ a2 ^ b3]
        state = list(xor_bytes(bytes(state), round_key))
    state = [SBOX[value] for value in state]
    shifted = [0] * 16
    for row in range(4):
        for column in range(4):
            shifted[4 * column + row] = state[4 * ((column + row) % 4) + row]
    return xor_bytes(bytes(shifted), round_keys[-1])


def ctr_crypt(data: bytes, key: bytes, counter: bytes, counter_bits: int = 128) -> bytes:
    if len(counter) != 16 or counter_bits not in (32, 64, 128):
        fail("invalid AES-CTR counter")
    prefix_length = 16 - counter_bits // 8
    prefix, number = counter[:prefix_length], int.from_bytes(counter[prefix_length:], "big")
    mask = (1 << counter_bits) - 1
    output = bytearray()
    for offset in range(0, len(data), 16):
        block_number = (number + offset // 16) & mask
        stream = aes_encrypt_block(prefix + block_number.to_bytes(16 - prefix_length, "big"), key)
        block = data[offset:offset + 16]
        output.extend(a ^ b for a, b in zip(block, stream))
    return bytes(output)


def v1_decrypt(content: str, password: str) -> bytes:
    try:
        ciphertext = base64.b64decode(content, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("v1 content is not valid base64") from exc
    if len(ciphertext) < 8:
        fail("v1 content is shorter than its 8-byte nonce")
    password_bytes = password.encode("utf-8")[:32].ljust(32, b"\0")
    first_block = aes_encrypt_block(password_bytes[:16], password_bytes)
    key = first_block + first_block
    return ctr_crypt(ciphertext[8:], key, ciphertext[:8] + b"\0" * 8, 64)


def parse_v2_envelope(content: str) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("v2 content is not JSON") from exc
    if not isinstance(value, dict) or value.get("deriv") != "PBKDF2" or value.get("iter") != V2_ITERATIONS or value.get("hash") != "SHA256" or value.get("salt") != V2_SALT.decode() or value.get("crypto") != "AES256CTR":
        fail("v2 envelope fields do not match Cryptiki 2.0")
    if not isinstance(value.get("iv"), str) or not re.fullmatch(r"[0-9a-fA-F]{32}", value["iv"]):
        fail("v2 envelope has an invalid IV")
    if not isinstance(value.get("encrypted"), str):
        fail("v2 envelope has no encrypted payload")
    return value


def v2_decrypt(content: str, passhash: bytes) -> bytes:
    envelope = parse_v2_envelope(content)
    try:
        encrypted = base64.b64decode(envelope["encrypted"], validate=True)
        iv = bytes.fromhex(envelope["iv"])
    except (ValueError, binascii.Error) as exc:
        raise ValueError("v2 encrypted payload is malformed") from exc
    return ctr_crypt(encrypted, passhash, iv, 128)


def ghash_multiply(left: int, right: int) -> int:
    result = 0
    reduction = 0xE1000000000000000000000000000000
    for _ in range(128):
        if right & (1 << 127):
            result ^= left
        right = (right << 1) & ((1 << 128) - 1)
        left = (left >> 1) ^ (reduction if left & 1 else 0)
    return result


def ghash(key: bytes, additional_data: bytes, ciphertext: bytes) -> bytes:
    h = int.from_bytes(aes_encrypt_block(b"\0" * 16, key), "big")
    state = 0
    padded = additional_data + b"\0" * ((16 - len(additional_data) % 16) % 16)
    padded += ciphertext + b"\0" * ((16 - len(ciphertext) % 16) % 16)
    padded += (len(additional_data) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    for offset in range(0, len(padded), 16):
        state = ghash_multiply(state ^ int.from_bytes(padded[offset:offset + 16], "big"), h)
    return state.to_bytes(16, "big")


def gcm_decrypt(blob: bytes, key: bytes, expected_format: int) -> dict[str, Any]:
    if len(blob) < 30 or blob[:2] != bytes((1, expected_format)):
        fail("capsule envelope header is invalid")
    nonce, ciphertext, tag = blob[2:14], blob[14:-16], blob[-16:]
    aad = CAPSULE_AAD_PREFIX + bytes((expected_format,))
    j0 = nonce + b"\0\0\0\1"
    expected_tag = xor_bytes(aes_encrypt_block(j0, key), ghash(key, aad, ciphertext))
    if not hmac.compare_digest(tag, expected_tag):
        fail("capsule AES-GCM authentication failed")
    payload = ctr_crypt(ciphertext, key, (int.from_bytes(j0, "big") + 1).to_bytes(16, "big"), 32)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("capsule payload is not valid JSON") from exc
    if not isinstance(value, dict) or value.get("capsuleFormat") != 1 or value.get("legacyFormat") != expected_format or not isinstance(value.get("content"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", str(value.get("contentHash", ""))):
        fail("capsule payload fields are invalid")
    return value


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output, previous = bytearray(), b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
    return bytes(output[:length])


def node_capsule_material(repo_root: Path, format_number: int, page: str, password: str, recovery_code: str, node: str) -> tuple[str, bytes]:
    script = r'''
import { readFileSync } from "node:fs";
import { argon2id } from "./src/vendor/argon2.js";
import { deriveLegacy, deriveCapsuleMaterial, hex } from "./src/migration-core.js";
const input = JSON.parse(readFileSync(0, "utf8"));
const material = await deriveLegacy(input.format, input.page, input.password, input.recoveryCode);
const capsule = await deriveCapsuleMaterial(input.format, material.keyhash, material.passhash, argon2id);
process.stdout.write(JSON.stringify({ lookupId: capsule.lookupId, wrapKey: hex(capsule.wrapKey) }));
'''
    request = json.dumps({"format": format_number, "page": page, "password": password, "recoveryCode": recovery_code})
    try:
        completed = subprocess.run([node, "--input-type=module", "-e", script], cwd=repo_root, input=request, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise ValueError(f"could not start Node.js for capsule check: {exc}") from exc
    if completed.returncode:
        raise ValueError("Node.js capsule key derivation failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Node.js returned invalid capsule key material") from exc
    return value["lookupId"], bytes.fromhex(value["wrapKey"])


def parse_sql_string(value: str, start: int) -> tuple[str, int]:
    if value[start] != "'":
        end = start
        while end < len(value) and value[end] not in ",)":
            end += 1
        token = value[start:end].strip()
        if not token or token.upper() == "NULL":
            fail("empty SQL field")
        return token, end
    start += 1
    output: list[str] = []
    while start < len(value):
        char = value[start]
        start += 1
        if char == "'":
            return "".join(output), start
        if char == "\\" and start < len(value):
            escaped = value[start]
            start += 1
            output.append({"0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", "'": "'", '"': '"', "\\": "\\", "%": "%", "_": "_"}.get(escaped, escaped))
        else:
            output.append(char)
    fail("unterminated SQL string")


def parse_legacy_dump(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    schema = re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?pages`?[\s\S]*?;", text, re.IGNORECASE)
    if not schema or any(not re.search(rf"\b{name}\b", schema.group(0), re.IGNORECASE) for name in ("id", "keyhash", "passhash", "contenthash", "content", "accessed", "modified")):
        fail("pages schema is missing or unexpected")
    insert_re = re.compile(r"INSERT\s+INTO\s+`?pages`?\s*(?:\([^;]*?\))?\s*VALUES\s*", re.IGNORECASE)
    rows: list[dict[str, Any]] = []
    for match in insert_re.finditer(text):
        at = match.end()
        end = at
        quoted = False
        escaped = False
        while end < len(text):
            char = text[end]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    quoted = False
            elif char == "'":
                quoted = True
            elif char == ";":
                break
            end += 1
        if end >= len(text):
            fail("unterminated INSERT statement")
        while at < end:
            while at < end and text[at].isspace():
                at += 1
            if at >= end:
                break
            if text[at] != "(":
                fail("expected SQL row tuple")
            at += 1
            values: list[str] = []
            for _ in range(7):
                while at < end and text[at].isspace():
                    at += 1
                value, at = parse_sql_string(text, at)
                values.append(value)
                while at < end and text[at].isspace():
                    at += 1
                if len(values) < 7:
                    if at >= end or text[at] != ",":
                        fail("expected SQL field separator")
                    at += 1
                elif at >= end or text[at] != ")":
                    fail("expected SQL row terminator")
                else:
                    at += 1
            row = dict(zip(("id", "keyhash", "passhash", "contenthash", "content", "accessed", "modified"), values))
            if not re.fullmatch(r"\d+", row["id"]) or not all(re.fullmatch(r"[0-9a-fA-F]{64}", row[name]) for name in ("keyhash", "passhash", "contenthash")):
                fail("legacy row has invalid metadata")
            rows.append({**row, "id": int(row["id"])})
            while at < end and text[at].isspace():
                at += 1
            if at < end:
                if text[at] != ",":
                    fail("unexpected SQL tuple separator")
                at += 1
    if not rows:
        fail("pages INSERT statement is missing")
    return rows


def load_capsule_jsonl(path: Path, lookup_id: str) -> bytes | None:
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if value.get("lookup_id") == lookup_id:
            try:
                return base64.urlsafe_b64decode(value["blob"] + "=" * ((4 - len(value["blob"]) % 4) % 4))
            except (KeyError, binascii.Error) as exc:
                raise ValueError("matching JSONL capsule has invalid base64") from exc
    return None


def fetch_capsule(url: str, lookup_id: str) -> tuple[int, bytes | None]:
    endpoint = url.rstrip("/") + "/api/legacy/recover"
    request = Request(endpoint, data=json.dumps({"lookupId": lookup_id}).encode(), headers={
        "Accept": "application/json",
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
        "User-Agent": "Cryptiki-legacy-diagnostic/1",
    }, method="POST")
    try:
        with urlopen(request, timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
            encoded = value.get("blob")
            if not isinstance(encoded, str):
                raise ValueError("recovery endpoint returned no capsule blob")
            return response.status, base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
    except HTTPError as exc:
        if exc.code == 404:
            return 404, None
        raise ValueError(f"recovery endpoint returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise ValueError(f"could not reach recovery endpoint: {exc}") from exc


def parse_entry_count(plaintext: bytes, format_number: int) -> int | None:
    try:
        text = plaintext.decode("utf-8")
        if format_number == 2:
            values = json.loads(text)
            return len(values) if isinstance(values, list) else None
        return sum(1 for line in text.splitlines() if re.match(r"^([^:\n]{1,256}):\s*(.*?)\s*/\s*(.*)$", line))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def verify(format_number: int, page: str, password: str, recovery_code: str, rows: list[dict[str, Any]], capsule_file: Path | None, remote_url: str | None, node: str, debug: bool) -> int:
    keyhash, passhash = derive_legacy(format_number, page, password, recovery_code)
    matching = [row for row in rows if row["keyhash"].lower() == keyhash.hex()]
    print(f"Loaded {len(rows)} legacy rows from the SQL dump.")
    print(f"Candidate format: v{format_number}")
    if not matching:
        print("[FAIL] page-name/recovery-code lookup: no row has this keyhash")
        print("       For v2, this means the page name or recovery code is not from the old v2 page/tab.")
        return 2
    if len(matching) != 1:
        print(f"[FAIL] lookup is ambiguous: {len(matching)} rows share the keyhash")
        return 2
    row = matching[0]
    print(f"[OK]   lookup matched legacy row id {row['id']}")
    stored_passhash = bytes.fromhex(row["passhash"])
    if not hmac.compare_digest(stored_passhash, passhash):
        print("[FAIL] password hash: password does not match this row")
        return 3
    print("[OK]   password hash matches the legacy row")
    try:
        if format_number == 1:
            plaintext = v1_decrypt(row["content"], password)
        else:
            parse_v2_envelope(row["content"])
            plaintext = v2_decrypt(row["content"], passhash)
        actual_hash = sha256(plaintext).hex()
    except (UnicodeDecodeError, ValueError, binascii.Error) as exc:
        print(f"[FAIL] legacy AES decryption: {exc}")
        return 4
    if not hmac.compare_digest(actual_hash, row["contenthash"].lower()):
        print("[FAIL] plaintext SHA-256 does not match the dump's contenthash")
        return 4
    entry_count = parse_entry_count(plaintext, format_number)
    print(f"[OK]   legacy AES decryption and content hash ({len(plaintext)} plaintext bytes, {entry_count if entry_count is not None else '?'} entries)")

    if not capsule_file and not remote_url:
        print("[INFO] capsule check skipped; supply --capsules FILE or --url https://cryptiki.com")
        return 0
    try:
        repo_root = Path(__file__).resolve().parents[1]
        lookup_id, wrap_key = node_capsule_material(repo_root, format_number, page, password, recovery_code, node)
        if debug:
            print(f"[DEBUG] v{format_number} lookup-ID prefix: {lookup_id[:12]}…")
        if capsule_file:
            capsule_blob = load_capsule_jsonl(capsule_file, lookup_id)
            source = str(capsule_file)
            if capsule_blob is None:
                print(f"[FAIL] capsule lookup in {source}: no matching lookup ID")
                return 5
        else:
            status, capsule_blob = fetch_capsule(remote_url or "", lookup_id)
            if debug:
                print(f"[DEBUG] v{format_number} recovery endpoint HTTP status: {status}")
            if status == 404 or capsule_blob is None:
                print("[FAIL] production capsule lookup: endpoint returned 404")
                print("       The raw dump works, so this is a capsule-derivation/import or deployment mismatch.")
                return 5
            source = remote_url or "remote endpoint"
        print(f"[OK]   capsule lookup returned a blob from {source} ({len(capsule_blob)} bytes)")
        capsule = gcm_decrypt(capsule_blob, wrap_key, format_number)
        if capsule["content"] != row["content"] or capsule["contentHash"].lower() != row["contenthash"].lower():
            print("[FAIL] capsule payload does not exactly match the SQL row")
            return 6
        print("[OK]   capsule AES-GCM authentication and SQL-row payload match")
        capsule_plaintext = v1_decrypt(capsule["content"], password) if format_number == 1 else v2_decrypt(capsule["content"], passhash)
        if not hmac.compare_digest(sha256(capsule_plaintext).hex(), capsule["contentHash"].lower()):
            print("[FAIL] capsule's legacy content hash verification")
            return 6
        print("[OK]   capsule legacy decryption and content hash verification")
        print("RESULT: the SQL row and recovery capsule both verify end-to-end; the browser failure is after these cryptographic steps.")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[FAIL] capsule verification: {exc}")
        return 6


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", required=True, type=Path, help="legacy SQL dump (kept outside the repository)")
    parser.add_argument("--format", choices=("auto", "1", "2"), default="auto", help="legacy format; auto tries v1 then v2")
    parser.add_argument("--capsules", type=Path, help="local capsules.jsonl produced by build-legacy-capsules.mjs")
    parser.add_argument("--url", help="deployment base URL; fetches only the opaque recovery lookup ID")
    parser.add_argument("--node", default="node", help="Node.js executable used for optional Argon2id capsule derivation")
    parser.add_argument("--debug", action="store_true", help="show safe stage details and a 12-character lookup-ID prefix")
    args = parser.parse_args()
    if not args.dump.is_file():
        parser.error(f"dump does not exist: {args.dump}")
    if args.capsules and not args.capsules.is_file():
        parser.error(f"capsules file does not exist: {args.capsules}")
    if args.capsules and args.url:
        parser.error("use only one of --capsules and --url")

    try:
        rows = parse_legacy_dump(args.dump)
    except (OSError, ValueError) as exc:
        print(f"Could not parse dump: {exc}", file=sys.stderr)
        return 1
    page = input("Old page name (exact spelling; do not add/remove spaces): ")
    password = getpass.getpass("Old password (hidden): ")
    recovery_code = getpass.getpass("Recovery code from the old page, hidden; blank to derive from page name: ").strip()
    formats = [int(args.format)] if args.format != "auto" else [1, 2]
    for format_number in formats:
        result = verify(format_number, page, password, recovery_code, rows, args.capsules, args.url, args.node, args.debug)
        if result == 0 or args.format != "auto":
            return result
        print("Trying the other legacy format…")
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
