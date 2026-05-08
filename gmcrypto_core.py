"""Core SM2, SM3, and SM4 primitives for the GMKit command-line tools."""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from pathlib import Path

try:
    from asn1crypto import keys, pem
    from asn1crypto.core import Integer, OctetString, Sequence
except ImportError as exc:  # pragma: no cover - depends on local environment
    raise SystemExit(
        "Missing dependency: asn1crypto\n"
        "Install it with: pip install -r requirements.txt"
    ) from exc


SM2_OID = "1.2.156.10197.1.301"
SM2_CURVE_NAME = "sm2p256v1"
PRIVATE_KEY_BYTES = 32
PUBLIC_KEY_BYTES = 65
RAW_PUBLIC_KEY_BYTES = 64
SDF_ECCREF_MAX_LEN = 64
SDF_SM2_BITS = 256
SM2_P = int(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    16,
)
SM2_A = int(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    16,
)
SM2_B = int(
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7"
    "F39789F515AB8F92DDBCBD414D940E93",
    16,
)
SM2_N = int(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
    16,
)
SM2_GX = int(
    "32C4AE2C1F1981195F9904466A39C994"
    "8FE30BBFF2660BE1715A4589334C74C7",
    16,
)
SM2_GY = int(
    "BC3736A2F4F6779C59BDCEE36B692153"
    "D0A9877CC62A474002DF32E52139F0A0",
    16,
)
SM2_G = (SM2_GX, SM2_GY)
Point = tuple[int, int] | None
SM3_IV = (
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
)
SM3_T_0_15 = 0x79CC4519
SM3_T_16_63 = 0x7A879D8A
SM4_BLOCK_SIZE = 16
SM4_SBOX = (
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
)
SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
SM4_CK = (
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
)


class SM2Ciphertext(Sequence):
    _fields = [
        ("x", Integer),
        ("y", Integer),
        ("hash", OctetString),
        ("ciphertext", OctetString),
    ]


def register_sm2_curve() -> None:
    keys.NamedCurve.register(SM2_CURVE_NAME, SM2_OID, PRIVATE_KEY_BYTES)


def clean_hex(value: str) -> str:
    cleaned = re.sub(r"[\s:_-]", "", value.strip())
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    return cleaned


def decode_hex(value: str, label: str) -> bytes:
    cleaned = clean_hex(value)
    if not cleaned:
        raise ValueError(f"{label} is empty")
    if len(cleaned) % 2:
        raise ValueError(f"{label} hex length must be even")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError(f"{label} contains non-hex characters")
    return bytes.fromhex(cleaned)


def decode_base64(value: str, label: str) -> bytes:
    cleaned = re.sub(r"\s+", "", value.strip())
    if not cleaned:
        raise ValueError(f"{label} is empty")
    try:
        return base64.b64decode(cleaned, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"{label} is not valid base64") from exc


def decode_raw_key(
    value: str,
    label: str,
    expected_lengths: tuple[int, ...],
    input_format: str,
) -> bytes:
    decoders = {
        "hex": decode_hex,
        "base64": decode_base64,
    }

    if input_format != "auto":
        decoded = decoders[input_format](value, label)
        validate_length(decoded, label, expected_lengths)
        return decoded

    errors: list[str] = []
    for name in ("hex", "base64"):
        try:
            decoded = decoders[name](value, label)
            validate_length(decoded, label, expected_lengths)
            return decoded
        except ValueError as exc:
            errors.append(f"{name}: {exc}")

    expected = " or ".join(f"{length} bytes" for length in expected_lengths)
    raise ValueError(
        f"{label} must be hex or base64 encoded raw key bytes ({expected}). "
        + "; ".join(errors)
    )


def validate_length(value: bytes, label: str, expected_lengths: tuple[int, ...]) -> None:
    if len(value) not in expected_lengths:
        expected = " or ".join(str(length) for length in expected_lengths)
        raise ValueError(f"{label} must be {expected} bytes, got {len(value)} bytes")


def parse_private_key(value: str, input_format: str) -> bytes:
    private_key = decode_raw_key(value, "private key", (PRIVATE_KEY_BYTES,), input_format)
    private_value = int.from_bytes(private_key, "big")
    if not 1 <= private_value < SM2_N:
        raise ValueError("private key must be in the range [1, n - 1]")
    return private_key


def parse_public_key(value: str, input_format: str) -> bytes:
    public_key = decode_raw_key(
        value,
        "public key",
        (PUBLIC_KEY_BYTES, RAW_PUBLIC_KEY_BYTES),
        input_format,
    )
    if len(public_key) == RAW_PUBLIC_KEY_BYTES:
        public_key = b"\x04" + public_key
    if public_key[0] != 0x04:
        raise ValueError("public key must be an uncompressed EC point starting with 04")
    if not is_public_key_on_curve(public_key):
        raise ValueError("public key point is not on the SM2 curve")
    return public_key


def encode_public_key(point: tuple[int, int]) -> bytes:
    x, y = point
    return b"\x04" + x.to_bytes(PRIVATE_KEY_BYTES, "big") + y.to_bytes(
        PRIVATE_KEY_BYTES,
        "big",
    )


def decode_public_key_point(public_key: bytes) -> tuple[int, int]:
    x = int.from_bytes(public_key[1:33], "big")
    y = int.from_bytes(public_key[33:65], "big")
    return x, y


def is_point_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    if not 0 <= x < SM2_P or not 0 <= y < SM2_P:
        return False
    return (y * y - (x * x * x + SM2_A * x + SM2_B)) % SM2_P == 0


def is_public_key_on_curve(public_key: bytes) -> bool:
    return is_point_on_curve(decode_public_key_point(public_key))


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right

    if x1 == x2 and (y1 + y2) % SM2_P == 0:
        return None

    if left == right:
        if y1 == 0:
            return None
        slope = ((3 * x1 * x1 + SM2_A) * pow(2 * y1, -1, SM2_P)) % SM2_P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, SM2_P)) % SM2_P

    x3 = (slope * slope - x1 - x2) % SM2_P
    y3 = (slope * (x1 - x3) - y1) % SM2_P
    return x3, y3


def scalar_multiply(scalar: int, point: tuple[int, int]) -> Point:
    result: Point = None
    addend: Point = point

    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1

    return result


def generate_sm2_key_pair() -> tuple[bytes, bytes]:
    private_value = secrets.randbelow(SM2_N - 1) + 1
    public_point = scalar_multiply(private_value, SM2_G)
    if public_point is None:
        raise RuntimeError("failed to generate public key point")
    return private_value.to_bytes(PRIVATE_KEY_BYTES, "big"), encode_public_key(public_point)


def validate_key_pair(private_key: bytes, public_key: bytes) -> None:
    private_value = int.from_bytes(private_key, "big")
    public_point = scalar_multiply(private_value, SM2_G)
    if public_point is None or encode_public_key(public_point) != public_key:
        raise ValueError("private key and public key do not match")


def left_pad_sdf_coordinate(value: bytes, label: str) -> bytes:
    if len(value) > SDF_ECCREF_MAX_LEN:
        raise ValueError(f"{label} is longer than {SDF_ECCREF_MAX_LEN} bytes")
    return b"\x00" * (SDF_ECCREF_MAX_LEN - len(value)) + value


def encode_sdf_bits(endian: str) -> bytes:
    if endian not in ("little", "big"):
        raise ValueError("SDF endian must be little or big")
    return SDF_SM2_BITS.to_bytes(4, endian)


def private_key_to_sdf(private_key: bytes, endian: str = "little") -> bytes:
    validate_length(private_key, "private key", (PRIVATE_KEY_BYTES,))
    return encode_sdf_bits(endian) + left_pad_sdf_coordinate(private_key, "private key")


def public_key_to_sdf(public_key: bytes, endian: str = "little") -> bytes:
    validate_length(public_key, "public key", (PUBLIC_KEY_BYTES,))
    if public_key[0] != 0x04:
        raise ValueError("public key must be an uncompressed EC point starting with 04")
    x = public_key[1:33]
    y = public_key[33:65]
    return (
        encode_sdf_bits(endian)
        + left_pad_sdf_coordinate(x, "public key x")
        + left_pad_sdf_coordinate(y, "public key y")
    )


def rotate_left(value: int, bits: int) -> int:
    bits %= 32
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def sm3_p0(value: int) -> int:
    return value ^ rotate_left(value, 9) ^ rotate_left(value, 17)


def sm3_p1(value: int) -> int:
    return value ^ rotate_left(value, 15) ^ rotate_left(value, 23)


def sm3_hash(data: bytes) -> bytes:
    bit_len = len(data) * 8
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend(bit_len.to_bytes(8, "big"))

    state = list(SM3_IV)
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        words = [
            int.from_bytes(block[index : index + 4], "big")
            for index in range(0, 64, 4)
        ]
        for index in range(16, 68):
            words.append(
                (
                    sm3_p1(
                        words[index - 16]
                        ^ words[index - 9]
                        ^ rotate_left(words[index - 3], 15)
                    )
                    ^ rotate_left(words[index - 13], 7)
                    ^ words[index - 6]
                )
                & 0xFFFFFFFF
            )
        mixed_words = [words[index] ^ words[index + 4] for index in range(64)]

        a, b, c, d, e, f, g, h = state
        for index in range(64):
            if index < 16:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
                constant = SM3_T_0_15
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e) & g)
                constant = SM3_T_16_63

            ss1 = rotate_left(
                (rotate_left(a, 12) + e + rotate_left(constant, index)) & 0xFFFFFFFF,
                7,
            )
            ss2 = ss1 ^ rotate_left(a, 12)
            tt1 = (ff + d + ss2 + mixed_words[index]) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + words[index]) & 0xFFFFFFFF
            d = c
            c = rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = rotate_left(f, 19)
            f = e
            e = sm3_p0(tt2)

        state = [
            state[0] ^ a,
            state[1] ^ b,
            state[2] ^ c,
            state[3] ^ d,
            state[4] ^ e,
            state[5] ^ f,
            state[6] ^ g,
            state[7] ^ h,
        ]

    return b"".join(value.to_bytes(4, "big") for value in state)


def sm3_kdf(shared: bytes, key_length: int) -> bytes:
    output = bytearray()
    counter = 1
    while len(output) < key_length:
        output.extend(sm3_hash(shared + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(output[:key_length])


def sm4_tau(value: int) -> int:
    output = 0
    for shift in (24, 16, 8, 0):
        output = (output << 8) | SM4_SBOX[(value >> shift) & 0xFF]
    return output


def sm4_l(value: int) -> int:
    return (
        value
        ^ rotate_left(value, 2)
        ^ rotate_left(value, 10)
        ^ rotate_left(value, 18)
        ^ rotate_left(value, 24)
    ) & 0xFFFFFFFF


def sm4_l_key(value: int) -> int:
    return (value ^ rotate_left(value, 13) ^ rotate_left(value, 23)) & 0xFFFFFFFF


def sm4_round_keys(key: bytes) -> list[int]:
    validate_length(key, "SM4 key", (SM4_BLOCK_SIZE,))
    mk = [int.from_bytes(key[index : index + 4], "big") for index in range(0, 16, 4)]
    key_words = [mk[index] ^ SM4_FK[index] for index in range(4)]
    round_keys: list[int] = []
    for index in range(32):
        next_key = key_words[index] ^ sm4_l_key(
            sm4_tau(key_words[index + 1] ^ key_words[index + 2] ^ key_words[index + 3] ^ SM4_CK[index])
        )
        round_keys.append(next_key)
        key_words.append(next_key)
    return round_keys


def sm4_crypt_block(block: bytes, round_keys: list[int]) -> bytes:
    validate_length(block, "SM4 block", (SM4_BLOCK_SIZE,))
    words = [int.from_bytes(block[index : index + 4], "big") for index in range(0, 16, 4)]
    for index in range(32):
        next_word = words[index] ^ sm4_l(
            sm4_tau(words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ round_keys[index])
        )
        words.append(next_word)
    return b"".join(words[index].to_bytes(4, "big") for index in (35, 34, 33, 32))


def sm4_encrypt_block(block: bytes, key: bytes) -> bytes:
    return sm4_crypt_block(block, sm4_round_keys(key))


def sm4_decrypt_block(block: bytes, key: bytes) -> bytes:
    return sm4_crypt_block(block, list(reversed(sm4_round_keys(key))))


def pkcs7_pad(data: bytes, block_size: int = SM4_BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = SM4_BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("invalid PKCS#7 padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


def sm4_encrypt_ecb(plaintext: bytes, key: bytes, padding: str = "pkcs7") -> bytes:
    if padding == "pkcs7":
        plaintext = pkcs7_pad(plaintext)
    elif padding == "none" and len(plaintext) % SM4_BLOCK_SIZE:
        raise ValueError("SM4 plaintext length must be a multiple of 16 bytes without padding")
    elif padding != "none":
        raise ValueError(f"unsupported padding: {padding}")

    round_keys = sm4_round_keys(key)
    return b"".join(
        sm4_crypt_block(plaintext[index : index + SM4_BLOCK_SIZE], round_keys)
        for index in range(0, len(plaintext), SM4_BLOCK_SIZE)
    )


def sm4_decrypt_ecb(ciphertext: bytes, key: bytes, padding: str = "pkcs7") -> bytes:
    if len(ciphertext) % SM4_BLOCK_SIZE:
        raise ValueError("SM4 ciphertext length must be a multiple of 16 bytes")
    round_keys = list(reversed(sm4_round_keys(key)))
    plaintext = b"".join(
        sm4_crypt_block(ciphertext[index : index + SM4_BLOCK_SIZE], round_keys)
        for index in range(0, len(ciphertext), SM4_BLOCK_SIZE)
    )
    if padding == "pkcs7":
        return pkcs7_unpad(plaintext)
    if padding == "none":
        return plaintext
    raise ValueError(f"unsupported padding: {padding}")


def sm4_encrypt_cbc(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    padding: str = "pkcs7",
) -> bytes:
    validate_length(iv, "SM4 IV", (SM4_BLOCK_SIZE,))
    if padding == "pkcs7":
        plaintext = pkcs7_pad(plaintext)
    elif padding == "none" and len(plaintext) % SM4_BLOCK_SIZE:
        raise ValueError("SM4 plaintext length must be a multiple of 16 bytes without padding")
    elif padding != "none":
        raise ValueError(f"unsupported padding: {padding}")

    round_keys = sm4_round_keys(key)
    previous = iv
    output = bytearray()
    for index in range(0, len(plaintext), SM4_BLOCK_SIZE):
        block = xor_bytes(plaintext[index : index + SM4_BLOCK_SIZE], previous)
        encrypted = sm4_crypt_block(block, round_keys)
        output.extend(encrypted)
        previous = encrypted
    return bytes(output)


def sm4_decrypt_cbc(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    padding: str = "pkcs7",
) -> bytes:
    validate_length(iv, "SM4 IV", (SM4_BLOCK_SIZE,))
    if len(ciphertext) % SM4_BLOCK_SIZE:
        raise ValueError("SM4 ciphertext length must be a multiple of 16 bytes")

    round_keys = list(reversed(sm4_round_keys(key)))
    previous = iv
    output = bytearray()
    for index in range(0, len(ciphertext), SM4_BLOCK_SIZE):
        block = ciphertext[index : index + SM4_BLOCK_SIZE]
        decrypted = sm4_crypt_block(block, round_keys)
        output.extend(xor_bytes(decrypted, previous))
        previous = block

    plaintext = bytes(output)
    if padding == "pkcs7":
        return pkcs7_unpad(plaintext)
    if padding == "none":
        return plaintext
    raise ValueError(f"unsupported padding: {padding}")


def increment_counter(counter: bytes) -> bytes:
    value = (int.from_bytes(counter, "big") + 1) % (1 << (SM4_BLOCK_SIZE * 8))
    return value.to_bytes(SM4_BLOCK_SIZE, "big")


def sm4_crypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_length(iv, "SM4 IV", (SM4_BLOCK_SIZE,))
    round_keys = sm4_round_keys(key)
    counter = iv
    output = bytearray()
    for index in range(0, len(data), SM4_BLOCK_SIZE):
        block = data[index : index + SM4_BLOCK_SIZE]
        keystream = sm4_crypt_block(counter, round_keys)
        output.extend(xor_bytes(block, keystream[: len(block)]))
        counter = increment_counter(counter)
    return bytes(output)


def sm4_crypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_length(iv, "SM4 IV", (SM4_BLOCK_SIZE,))
    round_keys = sm4_round_keys(key)
    feedback = iv
    output = bytearray()
    for index in range(0, len(data), SM4_BLOCK_SIZE):
        block = data[index : index + SM4_BLOCK_SIZE]
        feedback = sm4_crypt_block(feedback, round_keys)
        output.extend(xor_bytes(block, feedback[: len(block)]))
    return bytes(output)


def sm4_encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    validate_length(iv, "SM4 IV", (SM4_BLOCK_SIZE,))
    round_keys = sm4_round_keys(key)
    feedback = iv
    output = bytearray()
    for index in range(0, len(plaintext), SM4_BLOCK_SIZE):
        block = plaintext[index : index + SM4_BLOCK_SIZE]
        keystream = sm4_crypt_block(feedback, round_keys)
        encrypted = xor_bytes(block, keystream[: len(block)])
        output.extend(encrypted)
        feedback = encrypted if len(encrypted) == SM4_BLOCK_SIZE else feedback
    return bytes(output)


def sm4_decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    validate_length(iv, "SM4 IV", (SM4_BLOCK_SIZE,))
    round_keys = sm4_round_keys(key)
    feedback = iv
    output = bytearray()
    for index in range(0, len(ciphertext), SM4_BLOCK_SIZE):
        block = ciphertext[index : index + SM4_BLOCK_SIZE]
        keystream = sm4_crypt_block(feedback, round_keys)
        output.extend(xor_bytes(block, keystream[: len(block)]))
        feedback = block if len(block) == SM4_BLOCK_SIZE else feedback
    return bytes(output)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def point_to_shared_bytes(point: tuple[int, int]) -> bytes:
    x, y = point
    return x.to_bytes(PRIVATE_KEY_BYTES, "big") + y.to_bytes(PRIVATE_KEY_BYTES, "big")


def sm2_encrypt(plaintext: bytes, public_key: bytes) -> tuple[tuple[int, int], bytes, bytes]:
    public_point = decode_public_key_point(public_key)
    if not is_point_on_curve(public_point):
        raise ValueError("public key point is not on the SM2 curve")

    while True:
        nonce = secrets.randbelow(SM2_N - 1) + 1
        c1_point = scalar_multiply(nonce, SM2_G)
        shared_point = scalar_multiply(nonce, public_point)
        if c1_point is None or shared_point is None:
            continue

        shared = point_to_shared_bytes(shared_point)
        mask = sm3_kdf(shared, len(plaintext))
        if any(mask):
            break

    c2 = xor_bytes(plaintext, mask)
    x2 = shared[:PRIVATE_KEY_BYTES]
    y2 = shared[PRIVATE_KEY_BYTES:]
    c3 = sm3_hash(x2 + plaintext + y2)
    return c1_point, c3, c2


def sm2_decrypt(private_key: bytes, ciphertext: bytes, ciphertext_format: str) -> bytes:
    c1_point, c3, c2 = parse_ciphertext(ciphertext, ciphertext_format)
    if not is_point_on_curve(c1_point):
        raise ValueError("ciphertext C1 point is not on the SM2 curve")

    private_value = int.from_bytes(private_key, "big")
    shared_point = scalar_multiply(private_value, c1_point)
    if shared_point is None:
        raise ValueError("invalid SM2 ciphertext")

    shared = point_to_shared_bytes(shared_point)
    mask = sm3_kdf(shared, len(c2))
    if not any(mask):
        raise ValueError("invalid SM2 ciphertext KDF output")

    plaintext = xor_bytes(c2, mask)
    x2 = shared[:PRIVATE_KEY_BYTES]
    y2 = shared[PRIVATE_KEY_BYTES:]
    expected_c3 = sm3_hash(x2 + plaintext + y2)
    if expected_c3 != c3:
        raise ValueError("SM2 ciphertext integrity check failed")
    return plaintext


def encode_ciphertext(
    c1_point: tuple[int, int],
    c3: bytes,
    c2: bytes,
    ciphertext_format: str,
) -> bytes:
    if ciphertext_format == "openssl-der":
        x, y = c1_point
        return SM2Ciphertext(
            {
                "x": x,
                "y": y,
                "hash": c3,
                "ciphertext": c2,
            }
        ).dump()

    c1 = encode_public_key(c1_point)
    if ciphertext_format == "c1c3c2":
        return c1 + c3 + c2
    if ciphertext_format == "c1c2c3":
        return c1 + c2 + c3
    raise ValueError(f"unsupported ciphertext format: {ciphertext_format}")


def parse_ciphertext(
    ciphertext: bytes,
    ciphertext_format: str,
) -> tuple[tuple[int, int], bytes, bytes]:
    if ciphertext_format == "openssl-der":
        try:
            parsed = SM2Ciphertext.load(ciphertext)
            c1_point = (parsed["x"].native, parsed["y"].native)
            c3 = parsed["hash"].native
            c2 = parsed["ciphertext"].native
            return c1_point, c3, c2
        except (ValueError, TypeError) as exc:
            raise ValueError("ciphertext is not valid OpenSSL SM2 DER") from exc

    if len(ciphertext) < PUBLIC_KEY_BYTES + PRIVATE_KEY_BYTES:
        raise ValueError("ciphertext is too short")

    c1 = ciphertext[:PUBLIC_KEY_BYTES]
    if c1[0] != 0x04:
        raise ValueError("raw ciphertext C1 must start with 04")
    c1_point = decode_public_key_point(c1)

    if ciphertext_format == "c1c3c2":
        c3 = ciphertext[PUBLIC_KEY_BYTES : PUBLIC_KEY_BYTES + PRIVATE_KEY_BYTES]
        c2 = ciphertext[PUBLIC_KEY_BYTES + PRIVATE_KEY_BYTES :]
        return c1_point, c3, c2
    if ciphertext_format == "c1c2c3":
        c2 = ciphertext[PUBLIC_KEY_BYTES:-PRIVATE_KEY_BYTES]
        c3 = ciphertext[-PRIVATE_KEY_BYTES:]
        return c1_point, c3, c2
    raise ValueError(f"unsupported ciphertext format: {ciphertext_format}")


def private_key_from_pem_file(path: Path) -> bytes:
    type_name, _, der = pem.unarmor(path.read_bytes())
    if isinstance(type_name, bytes):
        type_name = type_name.decode("ascii")
    if type_name == "PRIVATE KEY":
        register_sm2_curve()
        private_info = keys.PrivateKeyInfo.load(der)
        ec_private_key = private_info["private_key"].parsed
    elif type_name == "EC PRIVATE KEY":
        register_sm2_curve()
        ec_private_key = keys.ECPrivateKey.load(der)
    else:
        raise ValueError(f"{path} is not a PRIVATE KEY or EC PRIVATE KEY PEM")

    private_value = ec_private_key["private_key"].native
    return private_value.to_bytes(PRIVATE_KEY_BYTES, "big")


def public_key_from_pem_file(path: Path) -> bytes:
    type_name, _, der = pem.unarmor(path.read_bytes())
    if isinstance(type_name, bytes):
        type_name = type_name.decode("ascii")
    if type_name != "PUBLIC KEY":
        raise ValueError(f"{path} is not a PUBLIC KEY PEM")
    public_info = keys.PublicKeyInfo.load(der)
    public_key = public_info["public_key"].native
    if len(public_key) != PUBLIC_KEY_BYTES or public_key[0] != 0x04:
        raise ValueError(f"{path} does not contain an uncompressed SM2 public key")
    if not is_public_key_on_curve(public_key):
        raise ValueError(f"{path} public key point is not on the SM2 curve")
    return public_key


def der_to_pem(der: bytes, label: str) -> str:
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----\n"


def sm2_parameters() -> keys.ECDomainParameters:
    return keys.ECDomainParameters(name="named", value=SM2_OID)


def build_ec_private_key(
    private_key: bytes,
    public_key: bytes | None = None,
) -> keys.ECPrivateKey:
    register_sm2_curve()
    key_data = {
        "version": "ecPrivkeyVer1",
        "private_key": int.from_bytes(private_key, "big"),
        "parameters": sm2_parameters(),
    }
    if public_key is not None:
        key_data["public_key"] = public_key
    return keys.ECPrivateKey(key_data)


def private_key_to_sec1_pem(
    private_key: bytes,
    public_key: bytes | None = None,
) -> str:
    return der_to_pem(build_ec_private_key(private_key, public_key).dump(), "EC PRIVATE KEY")


def private_key_to_pkcs8_pem(
    private_key: bytes,
    public_key: bytes | None = None,
) -> str:
    private_info = keys.PrivateKeyInfo(
        {
            "version": 0,
            "private_key_algorithm": {
                "algorithm": "ec",
                "parameters": sm2_parameters(),
            },
            "private_key": build_ec_private_key(private_key, public_key),
        }
    )
    return der_to_pem(private_info.dump(), "PRIVATE KEY")


def public_key_to_pem(public_key: bytes) -> str:
    pki = keys.PublicKeyInfo(
        {
            "algorithm": {
                "algorithm": "ec",
                "parameters": sm2_parameters(),
            },
            "public_key": public_key,
        }
    )
    return der_to_pem(pki.dump(), "PUBLIC KEY")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="ascii")


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)
