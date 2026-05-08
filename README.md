# GMKit

GMKit is a lightweight command-line toolkit for Chinese commercial cryptography
workflows. It currently provides separate tools for SM2, SM3, and SM4:

- `gm-sm2`: SM2 key generation, PEM wrapping/conversion, encryption, and decryption
- `gm-sm3`: SM3 digest calculation
- `gm-sm4`: SM4 encryption and decryption

[中文文档](README.zh-CN.md)

The tools are designed for interoperability work, local testing, and small
automation scripts. GMKit does not require OpenSSL at runtime; OpenSSL is only
used by optional interoperability regression tests when available.

## Install

```bash
pip install -r requirements.txt
```

For development and tests:

```bash
pip install -r requirements-dev.txt
```

## SM2 Tool

Generate a random SM2 key pair:

```bash
./gm-sm2 --generate
```

Default output files:

- private key: `sm2.key.pem`
- public key: `sm2.pub.pem`

Print raw generated key values as hex/base64:

```bash
./gm-sm2 --generate --print-raw
```

Convert an existing raw key pair to PEM:

```bash
./gm-sm2 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=
```

SM2 public key input may be hex/base64 `04 + x + y`, or raw `x + y`; the `04`
prefix is added automatically for raw `x + y`.

Encrypt with an SM2 public key PEM:

```bash
./gm-sm2 \
  --encrypt \
  --public-key-pem sm2.pub.pem \
  --in plain.txt \
  --out cipher.der
```

Decrypt with an SM2 private key PEM:

```bash
./gm-sm2 \
  --decrypt \
  --private-key-pem sm2.key.pem \
  --in cipher.der \
  --out decrypted.txt
```

SM2 ciphertext formats:

- `openssl-der`: OpenSSL-compatible ASN.1 DER, default
- `c1c3c2`: raw `04+x+y || C3 || C2`
- `c1c2c3`: raw `04+x+y || C2 || C3`

The generated PEM files include the SM2 curve OID:

```text
1.2.156.10197.1.301
```

The built-in SM2 curve parameters follow
[RFC 8998 curveSM2](https://www.rfc-editor.org/rfc/rfc8998#section-3.2).

## SM3 Tool

Calculate an SM3 digest for a file:

```bash
./gm-sm3 --in message.txt
```

Write the digest to a file:

```bash
./gm-sm3 --in message.txt --out message.sm3
```

Output formats:

```bash
./gm-sm3 --in message.txt --format hex
./gm-sm3 --in message.txt --format base64
./gm-sm3 --in message.txt --format binary --out message.sm3.bin
```

If `--in` is omitted, `gm-sm3` reads from stdin.

## SM4 Tool

Generate a random SM4 key and IV:

```bash
./gm-sm4 --generate-key
./gm-sm4 --generate-iv
```

Encrypt with SM4-CBC and PKCS#7 padding:

```bash
./gm-sm4 \
  --encrypt \
  --mode cbc \
  --key 0123456789abcdeffedcba9876543210 \
  --iv 00000000000000000000000000000000 \
  --in plain.txt \
  --out cipher.bin
```

Decrypt:

```bash
./gm-sm4 \
  --decrypt \
  --mode cbc \
  --key 0123456789abcdeffedcba9876543210 \
  --iv 00000000000000000000000000000000 \
  --in cipher.bin \
  --out decrypted.txt
```

Supported SM4 options:

- modes: `cbc`, `ecb`, `ctr`, `ofb`, `cfb`
- padding for `cbc`/`ecb`: `pkcs7`, `none`
- key/IV encoding: `auto`, `hex`, `base64`
- input/output encoding: `raw`, `hex`, `base64`

## Tests

Run all tests:

```bash
pytest -q
```

The test suite covers:

- SM2 key generation and encryption/decryption
- SM2/OpenSSL ciphertext interoperability when OpenSSL exposes SM2 support
- SM3 known vector
- SM3/OpenSSL digest interoperability when OpenSSL exposes SM3 support
- SM4 known vector
- SM4 file round trips for CBC, CTR, OFB, and CFB
- SM4/OpenSSL ciphertext interoperability for CBC, CTR, OFB, and CFB when
  OpenSSL exposes SM4 support

OpenSSL interoperability tests are skipped automatically when OpenSSL is missing
or does not expose the relevant SM2, SM3, or SM4 support.

## Product Direction

Current scope is a CLI-first GM toolkit for SM2, SM3, and SM4 interoperability.
The next product steps are packaging and polish:

- PyPI/pipx installation
- stable command help and examples
- more test vectors and cross-language fixtures
- optional Python library API

## Security Note

Do not commit real private keys. Generated `*.pem` and `*.key` files are ignored
by this repository's `.gitignore`.

The built-in Python cryptographic implementations are intended for tooling and
interoperability workflows. For high-assurance production systems, prefer an
audited cryptographic provider or hardware-backed key storage.
