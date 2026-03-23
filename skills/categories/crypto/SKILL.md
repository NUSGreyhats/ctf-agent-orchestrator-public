---
name: crypto
description: Use when the challenge involves cryptography — breaking RSA, AES, ECC, lattice/LWE, PRNG prediction, classical ciphers, padding oracles, signature forgery, or ZKP exploitation. Also use when you see .sage files, ciphertext with number-heavy .txt files, or modular arithmetic in challenge source.
---

# CTF Cryptography

Quick reference for crypto CTF challenges. Identify the cryptosystem from the challenge source or ciphertext structure, then apply the matching attack below.

## Classic Ciphers

- **Caesar:** Brute force 26 keys or frequency analysis
- **Vigenere:** Known plaintext with flag format prefix; derive key from `(ct - pt) mod 26`. Kasiski examination for unknown key length
- **Substitution:** Frequency analysis, quipqiup.com for automated solving
- **Multi-byte XOR:** Split ciphertext by key position, frequency-analyze each column; score by English letter frequency (space = 0x20)
- **OTP key reuse (many-time pad):** `C1 XOR C2 XOR known_P = unknown_P`; crib dragging when no plaintext known

```python
from pwn import xor
xor(ciphertext, key)
```

## RSA Attacks

- **Small e with small message:** Take eth root directly
- **Common modulus:** Extended GCD attack when same message encrypted with two coprime exponents
- **Wiener's attack:** Small private exponent d — continued fraction on e/n
- **Fermat factorization:** p and q close together — `isqrt(n)` and search
- **Pollard's p-1:** p-1 has only small factors
- **Hastad's broadcast:** Same message, multiple e=3 encryptions — CRT
- **Coppersmith:** Partially known prime — `f.small_roots()` in SageMath

```python
# Basic RSA
from Crypto.Util.number import inverse, long_to_bytes
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

```bash
# Automated RSA attack suite
python RsaCtfTool.py -n <n> -e <e> --uncipher <c>
```

## AES / Block Cipher Attacks

- **ECB:** Block shuffling, byte-at-a-time oracle; image ECB preserves visual patterns
- **CBC bit flipping:** Modify ciphertext byte to change corresponding plaintext byte
- **CBC padding oracle:** Byte-by-byte decryption by testing padding validity (~4096 queries per block)
- **CFB-8:** Static IV with 8-bit feedback allows state reconstruction after 16 known bytes
- **AES-GCM:** Nonce reuse leaks authentication key H via polynomial GCD

## Elliptic Curve Attacks

- **Small subgroup:** Check curve order for small factors; Pohlig-Hellman + CRT
- **Invalid curve:** Send points on weaker curves if validation missing
- **Smart's attack:** Anomalous curves (order = p); p-adic lift solves DLP in O(1)
- **ECDSA nonce reuse:** Same r in two signatures leaks private key d

## Lattice / LWE

- **LWE via CVP (Babai):** Construct lattice from `[q*I | 0; A^T | I]`, use fpylll CVP to find closest vector
- **LLL:** Short vector reveals hidden factors in approximate GCD
- **Multi-layer challenges:** Geometry → subspace recovery → LWE → AES-GCM decryption chain

## PRNG Attacks

- **MT19937 (Python random):** 624 consecutive outputs → full state recovery via `randcrack`
- **LCG:** Known outputs → solve for a, b, m
- **V8 Math.random (XorShift128+):** 5-10 outputs + Z3 QF_BV solver recovers state
- **C srand/rand:** Use `ctypes.CDLL('libc.so.6')` to call C's `srand(time)` and `rand()` directly
- **Time-based seeds:** `srand(time(NULL))` — sync clock and predict

## ZKP / Constraint Solving

- **ZKP cheating:** For impossible problems, find hash collisions or predict PRNG salts
- **Z3 solver:** `BitVec` for bit-level, `Int` for arbitrary precision

```python
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(length)]
s = Solver()
# Add constraints from challenge
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[f].as_long()) for f in flag))
```

## Common Patterns

- **XOR with known plaintext:** `flag{` as crib to recover key
- **Deterministic OTP:** Known-plaintext XOR to recover keystream
- **Custom MAC forgery:** Linear XOR-based signing — recover secrets from known pairs
- **Hash length extension:** `SHA-256(SECRET || msg)` forgeable with `hlextend`

## Tools

- **Python:** `pip install pycryptodome z3-solver sympy gmpy2`
- **SageMath:** Required for ECC, Coppersmith, lattice attacks
- **RsaCtfTool:** Automated RSA attack suite
- **quipqiup.com:** Substitution cipher solver
- **randcrack:** MT19937 state recovery
