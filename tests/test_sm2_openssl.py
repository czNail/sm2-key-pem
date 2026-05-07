from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "sm2-key-pem"


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
