import os
import secrets

# GF(2^256) irreducible polynomial: x^256 + x^10 + x^5 + x^2 + 1
IRR_POLY = (1 << 256) | (1 << 10) | (1 << 5) | (1 << 2) | 1

class GF2_256:
    @staticmethod
    def add(a: int, b: int) -> int:
        return a ^ b

    @staticmethod
    def mul(a: int, b: int) -> int:
        result = 0
        for i in range(256):
            if b & 1:
                result ^= a
            carry = a >> 255
            a = (a << 1) & ((1 << 256) - 1)
            if carry:
                a ^= IRR_POLY & ((1 << 256) - 1)
            b >>= 1
        return result

    @staticmethod
    def pow(base: int, exp: int) -> int:
        result = 1
        while exp > 0:
            if exp & 1:
                result = GF2_256.mul(result, base)
            base = GF2_256.mul(base, base)
            exp >>= 1
        return result

    @staticmethod
    def inv(a: int) -> int:
        if a == 0:
            raise ValueError("Cannot invert zero")
        # Fermat: a^(2^256 - 2) = a^(-1) in GF(2^256)
        return GF2_256.pow(a, (1 << 256) - 2)

    @staticmethod
    def sub(a: int, b: int) -> int:
        return a ^ b

    @staticmethod
    def div(a: int, b: int) -> int:
        return GF2_256.mul(a, GF2_256.inv(b))


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder='big')


def _pad_secret(data: bytes) -> bytes:
    length = len(data)
    chunk_size = 32
    if length % chunk_size == 0:
        return data
    padded_length = ((length // chunk_size) + 1) * chunk_size
    return data.ljust(padded_length, b'\0')


def _split_chunk(chunk: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
    secret_int = _bytes_to_int(chunk)
    coeffs = [secret_int] + [secrets.randbits(256) for _ in range(k - 1)]
    shares = []
    for i in range(1, n + 1):
        x = i
        y = coeffs[0]
        xi = x
        for j in range(1, k):
            term = GF2_256.mul(coeffs[j], xi)
            y = GF2_256.add(y, term)
            xi = GF2_256.mul(xi, x)
        shares.append((x, y))
    return shares


def split_secret(secret: str, n: int, k: int) -> list[dict]:
    if k < 2:
        raise ValueError("Threshold k must be at least 2")
    if n < k:
        raise ValueError("n must be >= k")
    if not secret:
        raise ValueError("Secret cannot be empty")

    data = secret.encode('utf-8')
    padded = _pad_secret(data)
    chunk_size = 32
    chunks = [padded[i:i + chunk_size] for i in range(0, len(padded), chunk_size)]

    share_map: dict[int, list[int]] = {i: [] for i in range(1, n + 1)}

    for chunk in chunks:
        chunk_shares = _split_chunk(chunk, n, k)
        for idx, (x, y) in enumerate(chunk_shares):
            share_map[x].append(y)

    shares = []
    for x, y_list in share_map.items():
        y_bytes = b''.join(_int_to_bytes(y, 32) for y in y_list)
        encoded = f"{x}:{y_bytes.hex()}"
        shares.append({
            "index": x,
            "value": encoded
        })

    return shares


def _reconstruct_chunk(shares: list[tuple[int, int]], k: int) -> bytes:
    result = 0
    for i in range(k):
        xi, yi = shares[i]
        numerator = 1
        denominator = 1
        for j in range(k):
            if i == j:
                continue
            xj = shares[j][0]
            numerator = GF2_256.mul(numerator, xj)
            denominator = GF2_256.mul(denominator, GF2_256.add(xi, xj))
        li = GF2_256.mul(yi, GF2_256.div(numerator, denominator))
        result = GF2_256.add(result, li)
    return _int_to_bytes(result, 32)


def reconstruct_secret(shares: list[dict]) -> str:
    if len(shares) < 2:
        raise ValueError("At least 2 shares are required")

    parsed = []
    for share in shares:
        raw = share["value"]
        parts = raw.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid share format: {raw}")
        x = int(parts[0])
        y_hex = parts[1]
        y_bytes = bytes.fromhex(y_hex)
        parsed.append((x, y_bytes))

    chunk_size = 32
    num_chunks = len(parsed[0][1]) // chunk_size
    k = len(parsed)

    all_chunks = []
    for ci in range(num_chunks):
        chunk_shares = []
        for x_val, y_data in parsed:
            chunk_bytes = y_data[ci * chunk_size:(ci + 1) * chunk_size]
            chunk_val = _bytes_to_int(chunk_bytes)
            chunk_shares.append((x_val, chunk_val))
        recovered = _reconstruct_chunk(chunk_shares, k)
        all_chunks.append(recovered)

    result_bytes = b''.join(all_chunks).rstrip(b'\0')
    return result_bytes.decode('utf-8')
