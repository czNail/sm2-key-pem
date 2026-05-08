from __future__ import annotations

import importlib.machinery
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SM2_CLI = ROOT / "gm-sm2"
SM3_CLI = ROOT / "gm-sm3"
SM4_CLI = ROOT / "gm-sm4"
CORE = ROOT / "gmcrypto_core.py"


def load_cli_module() -> object:
    loader = importlib.machinery.SourceFileLoader("gmcrypto_core", str(CORE))
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


def require_openssl_digest(digest_name: str) -> str:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is not installed")

    result = run_command([openssl, "list", "-digest-algorithms"])
    if result.returncode != 0:
        pytest.skip(f"cannot inspect OpenSSL digest algorithms: {result.stderr.strip()}")

    if digest_name.lower() not in result.stdout.lower():
        pytest.skip(f"OpenSSL does not expose {digest_name} digest support")

    return openssl


def require_openssl_cipher(cipher_name: str) -> str:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is not installed")

    result = run_command([openssl, "list", "-cipher-algorithms"])
    if result.returncode != 0:
        pytest.skip(f"cannot inspect OpenSSL cipher algorithms: {result.stderr.strip()}")

    if cipher_name.lower() not in result.stdout.lower():
        pytest.skip(f"OpenSSL does not expose {cipher_name} cipher support")

    return openssl


def test_sm3_known_vector() -> None:
    gmcrypto_core = load_cli_module()
    assert (
        gmcrypto_core.sm3_hash(b"abc").hex()
        == "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0"
    )


def test_gm_sm3_cli_known_vector(tmp_path: Path) -> None:
    data = tmp_path / "abc.txt"
    digest = tmp_path / "abc.sm3"
    data.write_bytes(b"abc")

    result = run_command(
        [
            sys.executable,
            str(SM3_CLI),
            "--in",
            str(data),
            "--out",
            str(digest),
        ]
    )
    assert result.returncode == 0, result.stderr
    assert (
        digest.read_text(encoding="ascii").strip()
        == "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0"
    )


def test_gm_sm3_cli_interoperates_with_openssl(tmp_path: Path) -> None:
    openssl = require_openssl_digest("sm3")
    data = tmp_path / "message.txt"
    gmkit_digest = tmp_path / "gmkit.sm3"
    message = b"gm-sm3 openssl interoperability regression\n"
    data.write_bytes(message)

    gmkit_result = run_command(
        [
            sys.executable,
            str(SM3_CLI),
            "--in",
            str(data),
            "--out",
            str(gmkit_digest),
        ]
    )
    assert gmkit_result.returncode == 0, gmkit_result.stderr

    openssl_result = run_command([openssl, "dgst", "-sm3", str(data)])
    assert openssl_result.returncode == 0, openssl_result.stderr
    openssl_digest = openssl_result.stdout.rsplit("=", 1)[1].strip()
    assert gmkit_digest.read_text(encoding="ascii").strip() == openssl_digest


def test_sm4_known_vector() -> None:
    gmcrypto_core = load_cli_module()
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
    ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    assert gmcrypto_core.sm4_encrypt_block(plaintext, key) == ciphertext
    assert gmcrypto_core.sm4_decrypt_block(ciphertext, key) == plaintext


def test_gm_sm4_cli_known_vector(tmp_path: Path) -> None:
    plaintext = tmp_path / "plain.hex"
    ciphertext = tmp_path / "cipher.hex"
    decrypted = tmp_path / "decrypted.hex"
    key = "0123456789abcdeffedcba9876543210"
    plaintext.write_text("0123456789abcdeffedcba9876543210\n", encoding="ascii")

    encrypted = run_command(
        [
            sys.executable,
            str(SM4_CLI),
            "--encrypt",
            "--mode",
            "ecb",
            "--padding",
            "none",
            "--key",
            key,
            "--in",
            str(plaintext),
            "--out",
            str(ciphertext),
            "--input-format",
            "hex",
            "--output-format",
            "hex",
        ]
    )
    assert encrypted.returncode == 0, encrypted.stderr
    assert ciphertext.read_text(encoding="ascii").strip() == "681edf34d206965e86b3e94f536e4246"

    decrypted_result = run_command(
        [
            sys.executable,
            str(SM4_CLI),
            "--decrypt",
            "--mode",
            "ecb",
            "--padding",
            "none",
            "--key",
            key,
            "--in",
            str(ciphertext),
            "--out",
            str(decrypted),
            "--input-format",
            "hex",
            "--output-format",
            "hex",
        ]
    )
    assert decrypted_result.returncode == 0, decrypted_result.stderr
    assert decrypted.read_text(encoding="ascii").strip() == "0123456789abcdeffedcba9876543210"


@pytest.mark.parametrize("mode", ("cbc", "ctr", "ofb", "cfb"))
def test_gm_sm4_cli_round_trip(tmp_path: Path, mode: str) -> None:
    plaintext = tmp_path / "plain.txt"
    ciphertext = tmp_path / "cipher.bin"
    decrypted = tmp_path / "decrypted.txt"
    plaintext.write_bytes(f"gm-sm4 {mode} regression".encode())

    args = [
        "--mode",
        mode,
        "--key",
        "0123456789abcdeffedcba9876543210",
        "--iv",
        "00000000000000000000000000000000",
    ]

    encrypted = run_command(
        [
            sys.executable,
            str(SM4_CLI),
            "--encrypt",
            *args,
            "--in",
            str(plaintext),
            "--out",
            str(ciphertext),
        ]
    )
    assert encrypted.returncode == 0, encrypted.stderr
    assert ciphertext.read_bytes() != plaintext.read_bytes()

    decrypted_result = run_command(
        [
            sys.executable,
            str(SM4_CLI),
            "--decrypt",
            *args,
            "--in",
            str(ciphertext),
            "--out",
            str(decrypted),
        ]
    )
    assert decrypted_result.returncode == 0, decrypted_result.stderr
    assert decrypted.read_bytes() == plaintext.read_bytes()


@pytest.mark.parametrize("mode", ("cbc", "ctr", "ofb", "cfb"))
def test_gm_sm4_cli_interoperates_with_openssl(tmp_path: Path, mode: str) -> None:
    openssl = require_openssl_cipher(f"sm4-{mode}")
    key = "0123456789abcdeffedcba9876543210"
    iv = "00000000000000000000000000000000"
    plaintext = tmp_path / "plain.txt"
    gmkit_ciphertext = tmp_path / f"gmkit-{mode}-cipher.bin"
    openssl_ciphertext = tmp_path / f"openssl-{mode}-cipher.bin"
    gmkit_decrypted = tmp_path / "gmkit-decrypted.txt"
    openssl_decrypted = tmp_path / "openssl-decrypted.txt"
    message = f"gm-sm4 {mode} openssl interoperability regression\n".encode()
    plaintext.write_bytes(message)

    gmkit_encrypted = run_command(
        [
            sys.executable,
            str(SM4_CLI),
            "--encrypt",
            "--mode",
            mode,
            "--key",
            key,
            "--iv",
            iv,
            "--in",
            str(plaintext),
            "--out",
            str(gmkit_ciphertext),
        ]
    )
    assert gmkit_encrypted.returncode == 0, gmkit_encrypted.stderr

    openssl_decrypted_result = run_command(
        [
            openssl,
            "enc",
            f"-sm4-{mode}",
            "-d",
            "-K",
            key,
            "-iv",
            iv,
            "-in",
            str(gmkit_ciphertext),
            "-out",
            str(openssl_decrypted),
        ]
    )
    assert openssl_decrypted_result.returncode == 0, openssl_decrypted_result.stderr
    assert openssl_decrypted.read_bytes() == message

    openssl_encrypted = run_command(
        [
            openssl,
            "enc",
            f"-sm4-{mode}",
            "-K",
            key,
            "-iv",
            iv,
            "-in",
            str(plaintext),
            "-out",
            str(openssl_ciphertext),
        ]
    )
    assert openssl_encrypted.returncode == 0, openssl_encrypted.stderr

    gmkit_decrypted_result = run_command(
        [
            sys.executable,
            str(SM4_CLI),
            "--decrypt",
            "--mode",
            mode,
            "--key",
            key,
            "--iv",
            iv,
            "--in",
            str(openssl_ciphertext),
            "--out",
            str(gmkit_decrypted),
        ]
    )
    assert gmkit_decrypted_result.returncode == 0, gmkit_decrypted_result.stderr
    assert gmkit_decrypted.read_bytes() == message


def test_cli_encrypts_and_decrypts_generated_sm2_key_pair(tmp_path: Path) -> None:
    private_key = tmp_path / "sm2.key.pem"
    public_key = tmp_path / "sm2.pub.pem"
    plaintext = tmp_path / "plain.txt"
    ciphertext = tmp_path / "cipher.der"
    decrypted = tmp_path / "decrypted.txt"

    generated = run_command(
        [
            sys.executable,
            str(SM2_CLI),
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
            str(SM2_CLI),
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
            str(SM2_CLI),
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


def test_gm_sm2_converts_base64_raw_key_to_sec1_ec_private_key(tmp_path: Path) -> None:
    private_key = tmp_path / "sm2.ec.key.pem"
    public_key = tmp_path / "sm2.pub.pem"

    result = run_command(
        [
            sys.executable,
            str(SM2_CLI),
            "--private-input-format",
            "base64",
            "--public-input-format",
            "base64",
            "--private-pem-format",
            "sec1",
            "--private-key",
            "ERERERERERERERERERERERERERERERERERERERERERE=",
            "--public-key",
            "BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=",
            "--private-out",
            str(private_key),
            "--public-out",
            str(public_key),
        ]
    )

    assert result.returncode == 0, result.stderr
    assert private_key.read_text(encoding="ascii").startswith(
        "-----BEGIN EC PRIVATE KEY-----"
    )
    assert public_key.read_text(encoding="ascii").startswith("-----BEGIN PUBLIC KEY-----")


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
            str(SM2_CLI),
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
            str(SM2_CLI),
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
            str(SM2_CLI),
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
            str(SM2_CLI),
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
