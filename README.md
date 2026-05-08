# sm2-key-pem

An SM2-focused command-line toolbox for key generation, PEM wrapping, key
format conversion, and SM2 encryption/decryption. It does not require a
high-version OpenSSL installation for its built-in SM2 operations.

[中文文档](README.zh-CN.md)

This tool is useful when you need to generate an SM2 key pair locally, encrypt
or decrypt SM2 ciphertext, or convert raw keys returned by an online SM2
generator, for example:

- public key: base64 or hex encoded `04 + x + y`
- private key: base64 or hex encoded 32-byte scalar

The generated PEM files include the SM2 curve OID:

```text
1.2.156.10197.1.301
```

The built-in SM2 curve parameters follow
[RFC 8998 curveSM2](https://www.rfc-editor.org/rfc/rfc8998#section-3.2).

## Product Scope

Current release:

- SM2 key pair generation
- SM2 raw key to PEM conversion
- SM2 PKCS#8 and SEC1 private key PEM output
- SM2 public key PEM output
- SM2 encryption/decryption
- OpenSSL-compatible SM2 ciphertext by default

Roadmap:

- SM3 digest CLI
- SM4 encryption/decryption CLI
- More packaging options, such as `pipx` and PyPI

## Install

```bash
pip install -r requirements.txt
```

If your Python environment is externally managed, create a virtual environment
first or install `asn1crypto` in the Python environment used to run this tool.

## Generate a Random Key Pair

Generate a random SM2 key pair and write PKCS#8 private key PEM plus public key
PEM:

```bash
./sm2-key-pem --generate
```

Default output files:

- private key: `sm2.key.pem`
- public key: `sm2.pub.pem`

Print the raw generated key values as hex/base64:

```bash
./sm2-key-pem --generate --print-raw
```

`--print-raw` prints the private key. Use it only when you really need to copy
the raw private scalar somewhere.

## Convert Existing Raw Keys

Convert an existing private/public key pair to PEM:

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=
```

The private key is written as PKCS#8 by default:

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

## Input Formats

Input format is detected automatically by default.

Public key input may be:

- hex `04 + x + y`, 65 bytes
- base64 of `04 + x + y`, 65 bytes
- hex or base64 of raw `x + y`, 64 bytes; the `04` prefix is added automatically

Private key input may be:

- hex of a 32-byte private scalar
- base64 of a 32-byte private scalar

When both private and public keys are provided, the tool verifies that they
belong to the same SM2 key pair.

You can force an input format:

```bash
./sm2-key-pem \
  --private-input-format hex \
  --public-input-format base64 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=
```

## Private Key PEM Formats

Generate the default PKCS#8 PEM:

```bash
./sm2-key-pem \
  --private-pem-format pkcs8 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111
```

Generate SEC1 `EC PRIVATE KEY` PEM:

```bash
./sm2-key-pem \
  --private-pem-format sec1 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111
```

Generate both private key formats:

```bash
./sm2-key-pem \
  --private-pem-format both \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111
```

When `both` is used:

- PKCS#8 output: `sm2.key.pem`
- SEC1 output: `sm2.ec.key.pem`

## Custom Output Paths

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg= \
  --private-out my-sm2.key.pem \
  --public-out my-sm2.pub.pem
```

## Print PEM Content

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg= \
  --print
```

## Encrypt and Decrypt

Generate a key pair:

```bash
./sm2-key-pem --generate
```

Encrypt with the public key PEM:

```bash
./sm2-key-pem \
  --encrypt \
  --public-key-pem sm2.pub.pem \
  --in plain.txt \
  --out cipher.der
```

Decrypt with the private key PEM:

```bash
./sm2-key-pem \
  --decrypt \
  --private-key-pem sm2.key.pem \
  --in cipher.der \
  --out decrypted.txt
```

The default ciphertext format is `openssl-der`, which is compatible with
`openssl pkeyutl`. Raw ciphertext formats are also available:

```bash
./sm2-key-pem \
  --encrypt \
  --public-key-pem sm2.pub.pem \
  --in plain.txt \
  --out cipher.bin \
  --ciphertext-format c1c3c2
```

Supported ciphertext formats:

- `openssl-der`: OpenSSL-compatible ASN.1 DER, default
- `c1c3c2`: raw `04+x+y || C3 || C2`
- `c1c2c3`: raw `04+x+y || C2 || C3`

## Tests

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the regression tests:

```bash
pytest -q
```

The test suite covers built-in SM2 encryption/decryption and OpenSSL
interoperability. OpenSSL regression tests are skipped automatically when
OpenSSL is missing or does not expose SM2 support.

## Security Note

Do not commit real private keys. Generated `*.pem` and `*.key` files are ignored
by this repository's `.gitignore`.

The built-in Python SM2 implementation is intended for tooling and
interoperability workflows. For high-assurance production systems, prefer an
audited cryptographic provider or hardware-backed key storage.
