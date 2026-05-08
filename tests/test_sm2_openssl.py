from __future__ import annotations

import importlib.machinery
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "sm2-key-pem"


def load_cli_module() -> object:
    loader = importlib.machinery.SourceFileLoader("sm2_key_pem", str(CLI))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run_command(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def require_openssl_sm2() -> str:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is not installed")

    result = run_command([openssl, "list", "-public-key-algorithms"])
    if result.returncode != 0:
        pytest.skip(f"cannot inspect OpenSSL algorithms: {result.stderr.strip()}")

    if "SM2" not in result.stdout and "sm2" not in result.stdout:
        pytest.skip("OpenSSL does not expose SM2 public-key support")

    return openssl


def test_sm3_known_vector() -> None:
    sm2_key_pem = load_cli_module()
    assert (
        sm2_key_pem.sm3_hash(b"abc").hex()
        == "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0"
    )


def test_cli_encrypts_and_decrypts_generated_sm2_key_pair(tmp_path: Path) -> None:
    private_key = tmp_path / "sm2.key.pem"
    public_key = tmp_path / "sm2.pub.pem"
    plaintext = tmp_path / "plain.txt"
    ciphertext = tmp_path / "cipher.der"
    decrypted = tmp_path / "decrypted.txt"

    generated = run_command(
        [
            sys.executable,
            str(CLI),
            "--generate",
            "--private-out",
            str(private_key),
            "--public-out",
            str(public_key),
        ]
    )
    assert generated.returncode == 0, generated.stderr

    message = b"sm2-key-pem pure python encryption regression\n"
    plaintext.write_bytes(message)

    encrypted = run_command(
        [
            sys.executable,
            str(CLI),
            "--encrypt",
            "--public-key-pem",
            str(public_key),
            "--in",
            str(plaintext),
            "--out",
            str(ciphertext),
        ]
    )
    assert encrypted.returncode == 0, encrypted.stderr
    assert ciphertext.read_bytes() != message

    decrypted_result = run_command(
        [
            sys.executable,
            str(CLI),
            "--decrypt",
            "--private-key-pem",
            str(private_key),
            "--in",
            str(ciphertext),
            "--out",
            str(decrypted),
        ]
    )
    assert decrypted_result.returncode == 0, decrypted_result.stderr
    assert decrypted.read_bytes() == message


def test_generated_sm2_key_pair_encrypts_and_decrypts_with_openssl(
    tmp_path: Path,
) -> None:
    openssl = require_openssl_sm2()
    private_key = tmp_path / "sm2.key.pem"
    public_key = tmp_path / "sm2.pub.pem"
    plaintext = tmp_path / "plain.txt"
    ciphertext = tmp_path / "cipher.bin"
    decrypted = tmp_path / "decrypted.txt"

    generated = run_command(
        [
            sys.executable,
            str(CLI),
            "--generate",
            "--private-out",
            str(private_key),
            "--public-out",
            str(public_key),
        ]
    )
    assert generated.returncode == 0, generated.stderr
    assert private_key.read_text(encoding="ascii").startswith("-----BEGIN PRIVATE KEY-----")
    assert public_key.read_text(encoding="ascii").startswith("-----BEGIN PUBLIC KEY-----")

    message = b"sm2-key-pem openssl encryption regression\n"
    plaintext.write_bytes(message)

    encrypted = run_command(
        [
            openssl,
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(public_key),
            "-in",
            str(plaintext),
            "-out",
            str(ciphertext),
        ]
    )
    assert encrypted.returncode == 0, encrypted.stderr
    assert ciphertext.read_bytes() != message

    decrypted_result = run_command(
        [
            openssl,
            "pkeyutl",
            "-decrypt",
            "-inkey",
            str(private_key),
            "-in",
            str(ciphertext),
            "-out",
            str(decrypted),
        ]
    )
    assert decrypted_result.returncode == 0, decrypted_result.stderr
    assert decrypted.read_bytes() == message


def test_cli_sm2_ciphertext_interoperates_with_openssl(tmp_path: Path) -> None:
    openssl = require_openssl_sm2()
    private_key = tmp_path / "sm2.key.pem"
    public_key = tmp_path / "sm2.pub.pem"
    plaintext = tmp_path / "plain.txt"
    cli_ciphertext = tmp_path / "cli-cipher.der"
    openssl_ciphertext = tmp_path / "openssl-cipher.der"
    cli_decrypted = tmp_path / "cli-decrypted.txt"
    openssl_decrypted = tmp_path / "openssl-decrypted.txt"

    generated = run_command(
        [
            sys.executable,
            str(CLI),
            "--generate",
            "--private-out",
            str(private_key),
            "--public-out",
            str(public_key),
        ]
    )
    assert generated.returncode == 0, generated.stderr

    message = b"sm2-key-pem openssl interoperability regression\n"
    plaintext.write_bytes(message)

    cli_encrypted = run_command(
        [
            sys.executable,
            str(CLI),
            "--encrypt",
            "--public-key-pem",
            str(public_key),
            "--in",
            str(plaintext),
            "--out",
            str(cli_ciphertext),
        ]
    )
    assert cli_encrypted.returncode == 0, cli_encrypted.stderr

    openssl_decrypted_result = run_command(
        [
            openssl,
            "pkeyutl",
            "-decrypt",
            "-inkey",
            str(private_key),
            "-in",
            str(cli_ciphertext),
            "-out",
            str(openssl_decrypted),
        ]
    )
    assert openssl_decrypted_result.returncode == 0, openssl_decrypted_result.stderr
    assert openssl_decrypted.read_bytes() == message

    openssl_encrypted = run_command(
        [
            openssl,
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(public_key),
            "-in",
            str(plaintext),
            "-out",
            str(openssl_ciphertext),
        ]
    )
    assert openssl_encrypted.returncode == 0, openssl_encrypted.stderr

    cli_decrypted_result = run_command(
        [
            sys.executable,
            str(CLI),
            "--decrypt",
            "--private-key-pem",
            str(private_key),
            "--in",
            str(openssl_ciphertext),
            "--out",
            str(cli_decrypted),
        ]
    )
    assert cli_decrypted_result.returncode == 0, cli_decrypted_result.stderr
    assert cli_decrypted.read_bytes() == message
