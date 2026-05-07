# sm2-key-pem

Convert raw SM2 public/private keys from hex or base64 to PEM.

[中文文档](README.zh-CN.md)

This tool is useful when an online SM2 generator returns raw keys, for example:

- public key: base64 or hex encoded `04 + x + y`
- private key: base64 or hex encoded 32-byte scalar

The generated PEM files include the SM2 curve OID:

```text
1.2.156.10197.1.301
```

## Install

```bash
pip install -r requirements.txt
```

If your Python environment is externally managed, create a virtual environment
first or install `asn1crypto` in the Python environment used to run this tool.

## Usage

Generate a PKCS#8 private key PEM and a public key PEM:

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BBERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=
```

Default output files:

- private key: `sm2.key.pem`
- public key: `sm2.pub.pem`

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

You can force an input format:

```bash
./sm2-key-pem \
  --private-input-format hex \
  --public-input-format base64 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BBERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=
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
  --public-key BBERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI= \
  --private-out my-sm2.key.pem \
  --public-out my-sm2.pub.pem
```

## Print PEM Content

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BBERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI= \
  --print
```

## Security Note

Do not commit real private keys. Generated `*.pem` and `*.key` files are ignored
by this repository's `.gitignore`.
