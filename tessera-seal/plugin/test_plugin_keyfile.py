#!/usr/bin/env python3
"""
test_plugin_keyfile.py — pytest coverage for the TesseraSeal reference plugin
(`tessera-seal-plugin-file`) keyfile format and the frame protocol.

Covers (TSEAL-00040 / TP-038, and TP-100 delivered early):
  - wrap/unwrap roundtrip under both KDFs (Argon2id, PBKDF2-HMAC-SHA-512)
  - fail-closed wrap when argon2-cffi is absent (explicit allow_pbkdf2 only,
    environment-independent)
  - unwrap selects the KDF from the file's KDF block, never the environment
  - wrong-passphrase failure
  - legacy-file compatibility (v1 and KDF-block-less v1.1 layouts)
  - KDF-block tamper / forged-params rejection
  - frame protocol: roundtrip, clean EOF, truncated/oversized frames
  - recipient URI encode/parse
  - env-passphrase channel hardening (TP-106): warning outside CI,
    TESSERA_SEAL_ALLOW_ENV_PASSPHRASE=1 / CI suppression, prompt fallback

Run:  cd tessera-seal/plugin && python3 -m pytest test_plugin_keyfile.py -v
"""
from __future__ import annotations

import base64
import dataclasses
import io
import secrets
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "python"))

import protocol  # noqa: E402
import tessera_seal_plugin_file as plugin  # noqa: E402

HAS_ARGON2 = plugin._argon2_available()

SK_LEN = plugin.tessera_seal.MLKEM1024_SK_BYTES   # 3168
PK_LEN = plugin.tessera_seal.MLKEM1024_PK_BYTES   # 1568

# Key contents are opaque to the wrap layer; random bytes keep the tests
# independent of kyber-py keygen time.
SK = secrets.token_bytes(SK_LEN)
PK = secrets.token_bytes(PK_LEN)
PASS = b"correct horse battery staple"
WRONG_PASS = b"incorrect horse battery staple"


def _hide_argon2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `from argon2.low_level import ...` raise ImportError."""
    monkeypatch.setitem(sys.modules, "argon2", None)
    monkeypatch.setitem(sys.modules, "argon2.low_level", None)


def _aesgcm_wrap(k_wrap: bytes, nonce: bytes, sk: bytes, aad: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = AESGCM(k_wrap).encrypt(nonce, sk, associated_data=aad)
    return blob[:-plugin.TAG_BYTES], blob[-plugin.TAG_BYTES:]


def _keyfile_bytes(header: str, blob: bytes) -> bytes:
    b64 = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
    return (header + "\n" + b64 + "\n").encode("ascii")


# ---------------------------------------------------------------------------
# Wrap/unwrap roundtrips — both KDFs
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
def test_wrap_unwrap_roundtrip_argon2id(tmp_path):
    kf = plugin._wrap_sk(SK, PK, PASS)
    assert kf.kdf is not None
    assert kf.kdf.kdf_id == plugin.KDF_ARGON2ID
    assert (kf.kdf.p0, kf.kdf.p1, kf.kdf.p2) == (
        plugin.ARGON2ID_MEMORY_KIB,
        plugin.ARGON2ID_TIME_COST,
        plugin.ARGON2ID_PARALLELISM,
    )
    raw = kf.serialize()
    kf2 = plugin.KeyFile.parse(raw)
    assert kf2 == kf
    assert plugin._unwrap_sk(kf2, PASS) == SK


def test_wrap_unwrap_roundtrip_pbkdf2_explicit_optin(monkeypatch):
    _hide_argon2(monkeypatch)
    kf = plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True)
    assert kf.kdf is not None
    assert kf.kdf.kdf_id == plugin.KDF_PBKDF2_HMAC_SHA512
    assert kf.kdf.p0 == plugin.PBKDF2_ITERATIONS
    raw = kf.serialize()
    kf2 = plugin.KeyFile.parse(raw)
    assert kf2.kdf == kf.kdf
    assert kf2.pk == PK
    assert plugin._unwrap_sk(kf2, PASS) == SK


def test_unwrap_selects_kdf_from_file_not_environment(monkeypatch):
    """A PBKDF2-wrapped file unwraps via PBKDF2 regardless of whether argon2
    is importable at unwrap time — the file's KDF block decides."""
    _hide_argon2(monkeypatch)
    raw = plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True).serialize()
    monkeypatch.undo()  # restore whatever argon2 availability the env has
    kf = plugin.KeyFile.parse(raw)
    assert kf.kdf is not None and kf.kdf.kdf_id == plugin.KDF_PBKDF2_HMAC_SHA512
    assert plugin._unwrap_sk(kf, PASS) == SK


# ---------------------------------------------------------------------------
# Fail-closed wrap (TSEAL-00040)
# ---------------------------------------------------------------------------


def test_wrap_fails_closed_without_argon2(monkeypatch):
    _hide_argon2(monkeypatch)
    with pytest.raises(SystemExit, match="argon2-cffi"):
        plugin._wrap_sk(SK, PK, PASS)


def test_wrap_fail_closed_is_env_independent(monkeypatch):
    """No environment variable may stand in for the explicit opt-in."""
    _hide_argon2(monkeypatch)
    for var in ("TESSERA_SEAL_ALLOW_PBKDF2", "TESSERA_SEAL_KDF", "ALLOW_PBKDF2"):
        monkeypatch.setenv(var, "1")
    with pytest.raises(SystemExit, match="argon2-cffi"):
        plugin._wrap_sk(SK, PK, PASS)


def test_unwrap_argon2_file_fails_closed_when_argon2_missing(monkeypatch):
    """A keyfile whose KDF block names Argon2id must hard-fail without
    argon2-cffi — never silently retry under PBKDF2."""
    kdf = plugin.KdfParams(
        plugin.KDF_ARGON2ID,
        plugin.ARGON2ID_MEMORY_KIB,
        plugin.ARGON2ID_TIME_COST,
        plugin.ARGON2ID_PARALLELISM,
    )
    kf = plugin.KeyFile(
        salt=secrets.token_bytes(plugin.SALT_BYTES),
        nonce=secrets.token_bytes(plugin.NONCE_BYTES),
        wrapped_sk=secrets.token_bytes(SK_LEN),
        tag=secrets.token_bytes(plugin.TAG_BYTES),
        pk=PK,
        kdf=kdf,
    )
    _hide_argon2(monkeypatch)
    with pytest.raises(SystemExit, match="argon2-cffi"):
        plugin._unwrap_sk(kf, PASS)


# ---------------------------------------------------------------------------
# Wrong passphrase / tamper
# ---------------------------------------------------------------------------


def test_wrong_passphrase_fails(monkeypatch):
    _hide_argon2(monkeypatch)
    kf = plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True)
    with pytest.raises(SystemExit, match="unwrap failed"):
        plugin._unwrap_sk(kf, WRONG_PASS)


def test_kdf_param_tamper_fails_unwrap(monkeypatch):
    """Tampering a KDF cost parameter changes K_wrap AND breaks the AAD
    binding — unwrap must fail."""
    _hide_argon2(monkeypatch)
    kf = plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True)
    tampered = dataclasses.replace(
        kf, kdf=dataclasses.replace(kf.kdf, p0=kf.kdf.p0 + 1)
    )
    with pytest.raises(SystemExit, match="unwrap failed"):
        plugin._unwrap_sk(tampered, PASS)


def test_kdf_id_flip_on_disk_rejected_at_parse(monkeypatch):
    """Flipping the on-disk kdf_id byte (PBKDF2 -> Argon2id) leaves PBKDF2's
    params, which are out of range for Argon2id — rejected at parse."""
    _hide_argon2(monkeypatch)
    raw = plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True).serialize()
    header, b64 = raw.decode("ascii").strip().splitlines()
    pad = (-len(b64)) % 4
    blob = bytearray(base64.urlsafe_b64decode(b64 + "=" * pad))
    blob[-plugin.KDF_BLOCK_BYTES] = plugin.KDF_ARGON2ID  # flip the kdf id byte
    with pytest.raises(ValueError):
        plugin.KeyFile.parse(_keyfile_bytes(header, bytes(blob)))


# ---------------------------------------------------------------------------
# Legacy-file compatibility
# ---------------------------------------------------------------------------


def _legacy_v11_file(monkeypatch) -> bytes:
    """Build a pre-TSEAL-00040 v1.1 keyfile (no KDF block) using the legacy
    PBKDF2 fallback derive (argon2 hidden for determinism)."""
    salt = secrets.token_bytes(plugin.SALT_BYTES)
    nonce = secrets.token_bytes(plugin.NONCE_BYTES)
    k_wrap = plugin._derive_kwrap_legacy(PASS, salt)
    wrapped, tag = _aesgcm_wrap(k_wrap, nonce, SK, plugin.KEYFILE_HEADER_V11.encode())
    return _keyfile_bytes(
        plugin.KEYFILE_HEADER_V11, salt + nonce + PK + wrapped + tag
    )


def test_legacy_v11_file_unwraps_as_before(monkeypatch):
    _hide_argon2(monkeypatch)
    raw = _legacy_v11_file(monkeypatch)
    kf = plugin.KeyFile.parse(raw)
    assert kf.kdf is None          # legacy layout — no KDF block
    assert kf.pk == PK             # embedded-pubkey query path needs no unwrap
    assert plugin._unwrap_sk(kf, PASS) == SK


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
def test_legacy_v11_argon2_file_unwraps_as_before():
    salt = secrets.token_bytes(plugin.SALT_BYTES)
    nonce = secrets.token_bytes(plugin.NONCE_BYTES)
    k_wrap = plugin._derive_kwrap_legacy(PASS, salt)
    wrapped, tag = _aesgcm_wrap(k_wrap, nonce, SK, plugin.KEYFILE_HEADER_V11.encode())
    raw = _keyfile_bytes(plugin.KEYFILE_HEADER_V11, salt + nonce + PK + wrapped + tag)
    kf = plugin.KeyFile.parse(raw)
    assert kf.kdf is None
    assert plugin._unwrap_sk(kf, PASS) == SK


def test_legacy_v1_file_unwraps_as_before(monkeypatch):
    _hide_argon2(monkeypatch)
    salt = secrets.token_bytes(plugin.SALT_BYTES)
    nonce = secrets.token_bytes(plugin.NONCE_BYTES)
    k_wrap = plugin._derive_kwrap_legacy(PASS, salt)
    wrapped, tag = _aesgcm_wrap(k_wrap, nonce, SK, plugin.KEYFILE_HEADER_V1.encode())
    raw = _keyfile_bytes(plugin.KEYFILE_HEADER_V1, salt + nonce + wrapped + tag)
    kf = plugin.KeyFile.parse(raw)
    assert kf.kdf is None
    assert kf.pk == b""            # v1 files do not embed pk
    assert plugin._unwrap_sk(kf, PASS) == SK


# ---------------------------------------------------------------------------
# Parse rejection — truncation, forged KDF blocks, bad headers
# ---------------------------------------------------------------------------


def _valid_v11_raw(monkeypatch) -> bytes:
    _hide_argon2(monkeypatch)
    return plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True).serialize()


def test_parse_rejects_truncated_and_extended_blob(monkeypatch):
    raw = _valid_v11_raw(monkeypatch)
    header, b64 = raw.decode("ascii").strip().splitlines()
    pad = (-len(b64)) % 4
    blob = base64.urlsafe_b64decode(b64 + "=" * pad)
    with pytest.raises(ValueError, match="length"):
        plugin.KeyFile.parse(_keyfile_bytes(header, blob[:-1]))
    with pytest.raises(ValueError, match="length"):
        plugin.KeyFile.parse(_keyfile_bytes(header, blob + b"\x00"))


def test_parse_rejects_unknown_header():
    with pytest.raises(ValueError, match="header"):
        plugin.KeyFile.parse(b"tseal-key-v9\nAAAA\n")


def test_parse_rejects_wrong_line_count():
    with pytest.raises(ValueError, match="two lines"):
        plugin.KeyFile.parse(b"tseal-key-v1.1\n")
    with pytest.raises(ValueError, match="two lines"):
        plugin.KeyFile.parse(b"tseal-key-v1.1\nAAAA\nBBBB\n")


def test_parse_rejects_unknown_kdf_id(monkeypatch):
    raw = _valid_v11_raw(monkeypatch)
    header, b64 = raw.decode("ascii").strip().splitlines()
    pad = (-len(b64)) % 4
    blob = bytearray(base64.urlsafe_b64decode(b64 + "=" * pad))
    blob[-plugin.KDF_BLOCK_BYTES] = 0x7F
    with pytest.raises(ValueError, match="unknown keyfile KDF id"):
        plugin.KeyFile.parse(_keyfile_bytes(header, bytes(blob)))


def test_parse_rejects_resource_exhaustion_params(monkeypatch):
    """A forged Argon2id block demanding absurd memory must be rejected at
    parse, before any derivation runs."""
    raw = _valid_v11_raw(monkeypatch)
    header, b64 = raw.decode("ascii").strip().splitlines()
    pad = (-len(b64)) % 4
    blob = bytearray(base64.urlsafe_b64decode(b64 + "=" * pad))
    forged = plugin.KdfParams.__new__(plugin.KdfParams)  # bypass validation
    object.__setattr__(forged, "kdf_id", plugin.KDF_ARGON2ID)
    object.__setattr__(forged, "p0", 0xFFFFFFFF)  # ~4 TiB in KiB — over cap
    object.__setattr__(forged, "p1", 3)
    object.__setattr__(forged, "p2", 1)
    blob[-plugin.KDF_BLOCK_BYTES:] = forged.encode()
    with pytest.raises(ValueError, match="memory_kib out of range"):
        plugin.KeyFile.parse(_keyfile_bytes(header, bytes(blob)))


def test_serialize_requires_kdf_block():
    kf = plugin.KeyFile(
        salt=secrets.token_bytes(plugin.SALT_BYTES),
        nonce=secrets.token_bytes(plugin.NONCE_BYTES),
        wrapped_sk=secrets.token_bytes(SK_LEN),
        tag=secrets.token_bytes(plugin.TAG_BYTES),
        pk=PK,
        kdf=None,
    )
    with pytest.raises(ValueError, match="KDF block"):
        kf.serialize()


# ---------------------------------------------------------------------------
# Embedded-pubkey (recipient URI) path
# ---------------------------------------------------------------------------


def test_pubkey_uri_roundtrip(monkeypatch):
    _hide_argon2(monkeypatch)
    kf = plugin.KeyFile.parse(
        plugin._wrap_sk(SK, PK, PASS, allow_pbkdf2=True).serialize()
    )
    uri = plugin._recipient_uri(kf.pk)
    rid = protocol.parse_recipient(uri)
    assert rid.plugin == plugin.PLUGIN_NAME
    assert rid.payload == PK


# ---------------------------------------------------------------------------
# Frame protocol (TP-100): roundtrip + truncated/oversized frames
# ---------------------------------------------------------------------------


def test_frame_roundtrip_sequence():
    buf = io.BytesIO()
    protocol.write_frame(buf, protocol.FRAME_UNWRAP_KEY, b"\x01" * 1568)
    protocol.write_ok(buf, b"\x02" * 32)
    protocol.write_error(buf, "boom")
    protocol.write_done(buf)
    buf.seek(0)
    f1 = protocol.read_frame(buf)
    assert (f1.type, f1.body) == (protocol.FRAME_UNWRAP_KEY, b"\x01" * 1568)
    f2 = protocol.read_frame(buf)
    assert (f2.type, f2.body) == (protocol.FRAME_OK, b"\x02" * 32)
    f3 = protocol.read_frame(buf)
    assert (f3.type, f3.body) == (protocol.FRAME_ERROR, b"boom")
    f4 = protocol.read_frame(buf)
    assert (f4.type, f4.body) == (protocol.FRAME_DONE, b"")
    assert protocol.read_frame(buf) is None  # clean EOF


def test_frame_empty_body_roundtrip():
    buf = io.BytesIO()
    protocol.write_frame(buf, protocol.FRAME_RECIPIENT_STANZA)
    buf.seek(0)
    f = protocol.read_frame(buf)
    assert (f.type, f.body) == (protocol.FRAME_RECIPIENT_STANZA, b"")


def test_frame_truncated_length_prefix():
    with pytest.raises(protocol.ProtocolError, match="truncated length prefix"):
        protocol.read_frame(io.BytesIO(b"\x00\x00"))


def test_frame_truncated_body():
    # Declares 10 bytes after the prefix but supplies only 3.
    with pytest.raises(protocol.ProtocolError, match="truncated frame body"):
        protocol.read_frame(io.BytesIO(b"\x00\x00\x00\x0a\x10\xaa\xbb"))


def test_frame_zero_length_rejected():
    with pytest.raises(protocol.ProtocolError, match="too small"):
        protocol.read_frame(io.BytesIO(b"\x00\x00\x00\x00"))


def test_frame_oversized_declared_length_rejected():
    too_big = protocol.MAX_FRAME_BODY_BYTES + 2
    hdr = too_big.to_bytes(4, "big")
    with pytest.raises(protocol.ProtocolError, match="frame too large"):
        protocol.read_frame(io.BytesIO(hdr))


def test_write_frame_oversized_body_rejected():
    class _NullWriter(io.RawIOBase):
        def write(self, b):  # pragma: no cover - never reached on reject
            return len(b)

    with pytest.raises(protocol.ProtocolError, match="body too large"):
        protocol.write_frame(
            _NullWriter(), protocol.FRAME_OK,
            b"\x00" * (protocol.MAX_FRAME_BODY_BYTES + 1),
        )


def test_write_frame_bad_type_rejected():
    with pytest.raises(protocol.ProtocolError, match="frame type"):
        protocol.write_frame(io.BytesIO(), 0x100, b"")


# ---------------------------------------------------------------------------
# Recipient URI parse failures
# ---------------------------------------------------------------------------


def test_parse_recipient_rejects_bad_prefix():
    with pytest.raises(protocol.ProtocolError, match="must start with"):
        protocol.parse_recipient("age1file1AAAA")


def test_parse_recipient_rejects_missing_separator():
    with pytest.raises(protocol.ProtocolError, match="separator"):
        protocol.parse_recipient("tseal1noseparator")


def test_parse_recipient_rejects_bad_plugin_name():
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_recipient("tseal1bad_name!1AAAA")


# ---------------------------------------------------------------------------
# Env-passphrase channel hardening (TP-106)
# ---------------------------------------------------------------------------


def test_env_passphrase_still_works_and_warns_outside_ci(monkeypatch, capsys):
    """TESSERA_SEAL_PASSPHRASE keeps working, but outside CI (and without the
    explicit acknowledgment) a one-line stderr warning names the leak surface."""
    monkeypatch.setenv("TESSERA_SEAL_PASSPHRASE", PASS.decode())
    monkeypatch.delenv("TESSERA_SEAL_ALLOW_ENV_PASSPHRASE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    assert plugin._read_passphrase() == PASS
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "TESSERA_SEAL_PASSPHRASE" in err
    assert err.count("\n") == 1  # one-line warning, not a wall of text


def test_env_passphrase_warning_suppressed_by_explicit_ack(monkeypatch, capsys):
    monkeypatch.setenv("TESSERA_SEAL_PASSPHRASE", PASS.decode())
    monkeypatch.setenv("TESSERA_SEAL_ALLOW_ENV_PASSPHRASE", "1")
    monkeypatch.delenv("CI", raising=False)
    assert plugin._read_passphrase() == PASS
    assert capsys.readouterr().err == ""


def test_env_passphrase_warning_suppressed_in_ci(monkeypatch, capsys):
    monkeypatch.setenv("TESSERA_SEAL_PASSPHRASE", PASS.decode())
    monkeypatch.delenv("TESSERA_SEAL_ALLOW_ENV_PASSPHRASE", raising=False)
    monkeypatch.setenv("CI", "true")
    assert plugin._read_passphrase() == PASS
    assert capsys.readouterr().err == ""


def test_env_passphrase_ack_must_be_exactly_1(monkeypatch, capsys):
    """Only the documented value '1' acknowledges; anything else still warns."""
    monkeypatch.setenv("TESSERA_SEAL_PASSPHRASE", PASS.decode())
    monkeypatch.setenv("TESSERA_SEAL_ALLOW_ENV_PASSPHRASE", "yes")
    monkeypatch.delenv("CI", raising=False)
    assert plugin._read_passphrase() == PASS
    assert "WARNING" in capsys.readouterr().err


def test_no_env_passphrase_falls_through_to_prompt(monkeypatch):
    """Without TESSERA_SEAL_PASSPHRASE the interactive getpass path is used
    (and never warns)."""
    monkeypatch.delenv("TESSERA_SEAL_PASSPHRASE", raising=False)
    monkeypatch.setattr(plugin.getpass, "getpass", lambda prompt: PASS.decode())
    assert plugin._read_passphrase() == PASS
