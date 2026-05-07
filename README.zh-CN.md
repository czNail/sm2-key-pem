# sm2-key-pem

生成随机 SM2 密钥对，或将 SM2 裸公钥、裸私钥从 hex/base64 转换成
PEM 文件；不要求本机安装高版本 OpenSSL。

[English README](README.md)

这个工具适合在本地生成 SM2 密钥对，也适合处理在线 SM2 工具生成的原始密钥，
例如：

- 公钥：base64 或 hex 编码的 `04 + x + y`
- 私钥：base64 或 hex 编码的 32 字节私钥标量

生成的 PEM 会写入 SM2 曲线 OID：

```text
1.2.156.10197.1.301
```

内置 SM2 曲线参数来自
[RFC 8998 curveSM2](https://www.rfc-editor.org/rfc/rfc8998#section-3.2)。

## 安装依赖

```bash
pip install -r requirements.txt
```

如果当前 Python 环境提示 `externally-managed-environment`，可以先创建虚拟环境，
或者在实际运行该工具的 Python 环境中安装 `asn1crypto`。

## 生成随机密钥对

生成随机 SM2 密钥对，并写出 PKCS#8 私钥 PEM 和公钥 PEM：

```bash
./sm2-key-pem --generate
```

默认输出文件：

- 私钥：`sm2.key.pem`
- 公钥：`sm2.pub.pem`

如果需要查看生成出来的裸 key，可以加 `--print-raw`：

```bash
./sm2-key-pem --generate --print-raw
```

`--print-raw` 会打印私钥，只在确实需要复制裸私钥时使用。

## 转换已有裸密钥

将已有私钥、公钥转换成 PEM：

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=
```

私钥默认输出为 PKCS#8 格式：

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

## 输入格式

默认会自动识别输入格式。

公钥可以是：

- hex 格式的 `04 + x + y`，65 字节
- base64 格式的 `04 + x + y`，65 字节
- hex 或 base64 格式的原始 `x + y`，64 字节；脚本会自动补 `04` 前缀

私钥可以是：

- 32 字节私钥标量的 hex
- 32 字节私钥标量的 base64

如果同时传入私钥和公钥，脚本会校验它们是否属于同一对 SM2 密钥。

也可以强制指定输入格式：

```bash
./sm2-key-pem \
  --private-input-format hex \
  --public-input-format base64 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg=
```

## 私钥 PEM 格式

生成默认的 PKCS#8 PEM：

```bash
./sm2-key-pem \
  --private-pem-format pkcs8 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111
```

生成 SEC1 `EC PRIVATE KEY` PEM：

```bash
./sm2-key-pem \
  --private-pem-format sec1 \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111
```

同时生成两种私钥格式：

```bash
./sm2-key-pem \
  --private-pem-format both \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111
```

使用 `both` 时：

- PKCS#8 输出：`sm2.key.pem`
- SEC1 输出：`sm2.ec.key.pem`

## 自定义输出文件

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg= \
  --private-out my-sm2.key.pem \
  --public-out my-sm2.pub.pem
```

## 打印 PEM 内容

```bash
./sm2-key-pem \
  --private-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --public-key BIUmEfdErwRWidz79MBDdzDS0t4zKrfw/AJ2nF+riolDfZOE8Zq4gu1miiiTbbkkdap5rvhpDuNvb7d8abm1cfg= \
  --print
```

## 测试

安装开发依赖：

```bash
pip install -r requirements-dev.txt
```

运行回归测试：

```bash
pytest -q
```

OpenSSL 回归测试会随机生成一对 SM2 密钥，用生成的公钥通过
`openssl pkeyutl` 加密数据，再用生成的私钥解密并比对明文。如果当前环境没有
OpenSSL，或者 OpenSSL 不暴露 SM2 支持，该测试会自动跳过。

## 安全提醒

不要提交真实私钥。仓库的 `.gitignore` 已经忽略生成的 `*.pem` 和 `*.key` 文件。
