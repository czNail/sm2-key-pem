# GMKit

GMKit 是一个轻量级国密命令行工具箱，当前提供三个相互独立的工具：

- `gm-sm2`：SM2 密钥生成、PEM 封装/转换、加密和解密
- `gm-sm3`：SM3 摘要计算
- `gm-sm4`：SM4 加密和解密

[English README](README.md)

这个项目面向互操作调试、本地测试和小型自动化脚本。GMKit 运行时不依赖
OpenSSL；OpenSSL 只在可用时用于可选的互操作回归测试。

## 安装

```bash
pip install -r requirements.txt
```

开发和测试依赖：

```bash
pip install -r requirements-dev.txt
```

## SM2 工具

生成随机 SM2 密钥对：

```bash
./gm-sm2 --generate
```

默认输出文件：

- 私钥：`sm2.key.pem`
- 公钥：`sm2.pub.pem`

打印生成出来的裸 key hex/base64：

```bash
./gm-sm2 --generate --print-raw
```

将已有裸密钥转换成 PEM：

```bash
./gm-sm2 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=
```

SM2 公钥可以是 hex/base64 编码的 `04 + x + y`，也可以是裸 `x + y`；
如果传入裸 `x + y`，工具会自动补 `04` 前缀。

使用 SM2 公钥 PEM 加密：

```bash
./gm-sm2 \
  --encrypt \
  --public-key-pem sm2.pub.pem \
  --in plain.txt \
  --out cipher.der
```

使用 SM2 私钥 PEM 解密：

```bash
./gm-sm2 \
  --decrypt \
  --private-key-pem sm2.key.pem \
  --in cipher.der \
  --out decrypted.txt
```

SM2 密文格式：

- `openssl-der`：OpenSSL 兼容 ASN.1 DER，默认格式
- `c1c3c2`：裸格式 `04+x+y || C3 || C2`
- `c1c2c3`：裸格式 `04+x+y || C2 || C3`

生成的 PEM 会写入 SM2 曲线 OID：

```text
1.2.156.10197.1.301
```

内置 SM2 曲线参数来自
[RFC 8998 curveSM2](https://www.rfc-editor.org/rfc/rfc8998#section-3.2)。

## SM3 工具

计算文件的 SM3 摘要：

```bash
./gm-sm3 --in message.txt
```

写入摘要文件：

```bash
./gm-sm3 --in message.txt --out message.sm3
```

输出格式：

```bash
./gm-sm3 --in message.txt --format hex
./gm-sm3 --in message.txt --format base64
./gm-sm3 --in message.txt --format binary --out message.sm3.bin
```

省略 `--in` 时，`gm-sm3` 从 stdin 读取数据。

## SM4 工具

生成随机 SM4 key 和 IV：

```bash
./gm-sm4 --generate-key
./gm-sm4 --generate-iv
```

使用 SM4-CBC 和 PKCS#7 padding 加密：

```bash
./gm-sm4 \
  --encrypt \
  --mode cbc \
  --key 0123456789abcdeffedcba9876543210 \
  --iv 00000000000000000000000000000000 \
  --in plain.txt \
  --out cipher.bin
```

解密：

```bash
./gm-sm4 \
  --decrypt \
  --mode cbc \
  --key 0123456789abcdeffedcba9876543210 \
  --iv 00000000000000000000000000000000 \
  --in cipher.bin \
  --out decrypted.txt
```

SM4 支持选项：

- 模式：`cbc`、`ecb`、`ctr`、`ofb`、`cfb`
- `cbc`/`ecb` padding：`pkcs7`、`none`
- key/IV 编码：`auto`、`hex`、`base64`
- 输入/输出编码：`raw`、`hex`、`base64`

## 测试

运行全部测试：

```bash
pytest -q
```

测试覆盖：

- SM2 密钥生成和加解密
- OpenSSL 暴露 SM2 支持时的 SM2/OpenSSL 密文互操作
- SM3 标准向量
- OpenSSL 暴露 SM3 支持时的 SM3/OpenSSL 摘要互操作
- SM4 标准向量
- SM4 CBC、CTR、OFB、CFB 文件加解密往返
- OpenSSL 暴露 SM4 支持时的 SM4 CBC、CTR、OFB、CFB 密文互操作

如果当前环境没有 OpenSSL，或者 OpenSSL 不暴露对应的 SM2、SM3、SM4 支持，
OpenSSL 互操作测试会自动跳过。

## 产品方向

当前定位是 CLI 优先的国密互操作工具箱，覆盖 SM2、SM3、SM4。后续产品化方向：

- PyPI/pipx 安装
- 稳定命令帮助和示例
- 更多测试向量和跨语言 fixtures
- 可选 Python library API

## 安全提醒

不要提交真实私钥。仓库的 `.gitignore` 已经忽略生成的 `*.pem` 和 `*.key` 文件。

内置 Python 密码实现主要面向工具化和互操作场景。高安全生产系统应优先使用经过
审计的密码库，或使用硬件/系统级密钥保护能力。
