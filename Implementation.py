#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
toy_dilithium_fixed.py
Implémentation pédagogique (NON SÉCURISÉE) inspirée de CRYSTALS-Dilithium.

Changements vs version précédente :
- t_pub = A * s1 (on n'ajoute plus s2 dans la clé publique).
- Vérification : mu est recalculé (on n'a plus besoin de le transmettre).
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Tuple, List

# ------------------------------------------------------------
# 1. Paramètres "jouet"
# ------------------------------------------------------------
@dataclass
class Params:
    n: int = 64               # taille du polynôme (vrai Dilithium : 256)
    q: int = 8380417          # même q que Dilithium
    eta: int = 2              # pour la distribution CBD
    k: int = 2                # dimensions de A (k x l)
    l: int = 2
    seed_bytes: int = 32
    hash_out: int = 32        # 256 bits (SHA-256 tronquée)
    debug: bool = False       # activer pour voir plus d'étapes

P = Params()

# ------------------------------------------------------------
# 2. Outils math sur polynômes
# ------------------------------------------------------------
def modq(x: int) -> int:
    return x % P.q

def poly_add(a: List[int], b: List[int]) -> List[int]:
    return [(x + y) % P.q for x, y in zip(a, b)]

def poly_sub(a: List[int], b: List[int]) -> List[int]:
    return [(x - y) % P.q for x, y in zip(a, b)]

def poly_mul(a: List[int], b: List[int]) -> List[int]:
    """
    Convolution naïve mod q et x^n + 1 (on boucle les indices).
    Complexité O(n^2) mais OK pour la démo.
    """
    n = P.n
    res = [0]*n
    for i in range(n):
        ai = a[i]
        for j in range(n):
            res[(i + j) % n] = (res[(i + j) % n] + ai * b[j]) % P.q
    return res

def poly_scalar_mul(a: List[int], s: int) -> List[int]:
    return [(x * s) % P.q for x in a]

# ------------------------------------------------------------
# 3. Hash & échantillonnage
# ------------------------------------------------------------
def shake128(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_128(data).digest(outlen)

def hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:P.hash_out]

def cbd(byte_stream: bytes, eta: int, n: int) -> List[int]:
    """
    Centered Binomial Distribution simplifiée.
    Pour chaque coeff : (nb_bits_1 sur eta bits) - (nb_bits_1 sur eta bits).
    """
    needed_bits = 2 * eta * n
    needed_bytes = (needed_bits + 7) // 8
    if len(byte_stream) < needed_bytes:
        raise ValueError("Pas assez de données pour le CBD")
    coeffs = []
    bitpos = 0
    for _ in range(n):
        a = 0
        b = 0
        for _ in range(eta):
            byte_index = bitpos // 8
            bit_index = bitpos % 8
            bitpos += 1
            a += (byte_stream[byte_index] >> bit_index) & 1
        for _ in range(eta):
            byte_index = bitpos // 8
            bit_index = bitpos % 8
            bitpos += 1
            b += (byte_stream[byte_index] >> bit_index) & 1
        coeffs.append((a - b) % P.q)
    return coeffs

def sample_small_vector(seed: bytes, nonce: int, length: int) -> List[List[int]]:
    """
    Génère 'length' polynômes CBD.
    """
    vec = []
    for i in range(length):
        stream = shake128(seed + nonce.to_bytes(2, "little") + i.to_bytes(2, "little"), 64)
        vec.append(cbd(stream, P.eta, P.n))
    return vec

def uniform_poly(seed: bytes, i: int, j: int) -> List[int]:
    """
    Polynôme uniforme mod q issu du seed (simplifié).
    """
    needed_bytes = 2 * P.n
    stream = shake128(seed + i.to_bytes(1, "little") + j.to_bytes(1, "little"), needed_bytes)
    poly = []
    for k in range(P.n):
        val = int.from_bytes(stream[2*k:2*k+2], "little") % P.q
        poly.append(val)
    return poly

def matA(seed: bytes) -> List[List[List[int]]]:
    """
    Matrice A de dimension k x l.
    """
    A = []
    for i in range(P.k):
        row = []
        for j in range(P.l):
            row.append(uniform_poly(seed, i, j))
        A.append(row)
    return A

# ------------------------------------------------------------
# 4. Structures de clé
# ------------------------------------------------------------
@dataclass
class PublicKey:
    rho: bytes
    t: List[List[int]]  # t_pub = A*s1

@dataclass
class SecretKey:
    rho: bytes
    s1: List[List[int]]
    s2: List[List[int]]
    t: List[List[int]]   # même que dans pk, conservé ici
    tr: bytes            # hash(pk)

# ------------------------------------------------------------
# 5. (Dé)Sérialisation simplifiée
# ------------------------------------------------------------
def serialize_poly(poly: List[int]) -> bytes:
    out = b""
    for x in poly:
        out += x.to_bytes(4, "little")  # 32 bits suffisent pour q
    return out

def serialize_vec(vec: List[List[int]]) -> bytes:
    return b"".join(serialize_poly(p) for p in vec)

# ------------------------------------------------------------
# 6. KeyGen
# ------------------------------------------------------------
def keygen() -> Tuple[PublicKey, SecretKey]:
    seed = os.urandom(P.seed_bytes)
    rho = hash256(seed + b"rho")
    rhoprime = hash256(seed + b"rhoprime")

    A = matA(rho)

    # Secrets
    s1 = sample_small_vector(rhoprime, nonce=0, length=P.l)
    s2 = sample_small_vector(rhoprime, nonce=1, length=P.k)

    # t_pub = A * s1  (PAS + s2)
    t_pub = []
    for i in range(P.k):
        acc = [0]*P.n
        for j in range(P.l):
            acc = poly_add(acc, poly_mul(A[i][j], s1[j]))
        t_pub.append(acc)

    pk = PublicKey(rho=rho, t=t_pub)
    tr = hash256(rho + serialize_vec(t_pub))
    sk = SecretKey(rho=rho, s1=s1, s2=s2, t=t_pub, tr=tr)

    if P.debug:
        print("[DEBUG] KeyGen:")
        print("  rho =", rho.hex()[:16], "...")
        print("  tr  =", tr.hex()[:16], "...")
    return pk, sk

# ------------------------------------------------------------
# 7. Signature
# ------------------------------------------------------------
def sign(sk: SecretKey, message: bytes) -> Tuple[List[List[int]], bytes]:
    # mu = H(tr || m)
    mu = hash256(sk.tr + message)

    # Tirage y (petit) avec un seed aléatoire
    y_seed = hash256(os.urandom(32) + b"y")
    y = sample_small_vector(y_seed, nonce=0, length=P.l)

    # w = A*y
    A = matA(sk.rho)
    w = []
    for i in range(P.k):
        acc = [0]*P.n
        for j in range(P.l):
            acc = poly_add(acc, poly_mul(A[i][j], y[j]))
        w.append(acc)

    # w1 : simplification -> division par 2
    w1 = [ [(coef // 2) % P.q for coef in poly] for poly in w ]

    # Challenge c
    c = hash256(mu + serialize_vec(w1))
    c_scalar = int.from_bytes(c, "little") % P.q

    # z = y + c*s1
    z = []
    for j in range(P.l):
        cs1 = poly_scalar_mul(sk.s1[j], c_scalar)
        z.append(poly_add(y[j], cs1))

    if P.debug:
        print("[DEBUG] Sign:")
        print("  mu =", mu.hex()[:16], "...")
        print("  c  =", c.hex()[:16], "...")
    # On renvoie (z, c). mu sera recalculé côté vérif.
    return z, c

# ------------------------------------------------------------
# 8. Vérification
# ------------------------------------------------------------
def verify(pk: PublicKey, message: bytes, z: List[List[int]], c: bytes) -> bool:
    # Recalcule tr & mu
    tr_check = hash256(pk.rho + serialize_vec(pk.t))
    mu_check = hash256(tr_check + message)

    c_scalar = int.from_bytes(c, "little") % P.q
    A = matA(pk.rho)

    # A*z
    Az = []
    for i in range(P.k):
        acc = [0]*P.n
        for j in range(P.l):
            acc = poly_add(acc, poly_mul(A[i][j], z[j]))
        Az.append(acc)

    # c * t_pub
    ct = []
    for i in range(P.k):
        ct.append(poly_scalar_mul(pk.t[i], c_scalar))

    # w' = A*z - c*t_pub
    wprime = []
    for i in range(P.k):
        wprime.append(poly_sub(Az[i], ct[i]))

    w1prime = [ [(coef // 2) % P.q for coef in poly] for poly in wprime ]

    # Challenge recalculé
    c_check = hash256(mu_check + serialize_vec(w1prime))

    if P.debug:
        print("[DEBUG] Verify:")
        print("  mu_check =", mu_check.hex()[:16], "...")
        print("  c_check  =", c_check.hex()[:16], "...")
    return c_check == c

# ------------------------------------------------------------
# 9. Démo
# ------------------------------------------------------------
def demo():
    # --- Cas 1 : signature valide avec (pk, sk) ---
    print("\n[1] Génération de clé pour le cas valide")
    pk, sk = keygen()
    print(f"  - rho (pub) : {pk.rho.hex()[:16]}...")
    print(f"  - t_pub : {len(pk.t)} polynômes de taille {P.n}")

    print("\n[2] Message")
    msg_text = "Bonjour, ceci est un message à signer !"
    msg = msg_text.encode("utf-8")
    print(f"  - message : {msg_text}")

    print("\n[3] Signature avec la clé valide")
    z, c = sign(sk, msg)
    print(f"  - z : {len(z)} polynômes")
    print(f"  - c : {c.hex()[:16]}...")

    print("\n[4] Vérification avec la même clé")
    ok = verify(pk, msg, z, c)
    print(f"  - Signature valide ? {ok}")
    if ok:
        print("  ✔️  OK, la signature est acceptée.")
    else:
        print("  ❌  Échec : incohérence (revérifier les modifs).")

    # --- Cas 2 : signature invalide avec une autre clé secrète (d'un usurpateur) ---
    print("\n[5] Génération d’une seconde paire de clés pour le cas invalide")
    pk2, sk2 = keygen()
    print(f"  - rho (pub2) : {pk2.rho.hex()[:16]}...")
    print(f"  - t_pub2 : {len(pk2.t)} polynômes de taille {P.n}")

    print("\n[6] Signature avec la clé secrète erronée (sk2)")
    z_bad, c_bad = sign(sk2, msg)
    print(f"  - c_bad : {c_bad.hex()[:16]}...")

    print("\n[7] Vérification avec la première clé publique (pk)")
    ok_bad = verify(pk, msg, z_bad, c_bad)
    print(f"  - Signature acceptée malgré la mauvaise clé ? {ok_bad}")
    if not ok_bad:
        print(" Comme attendu, la vérification échoue car la clé secrète utilisée n'est pas la bonne (clé de l'usurpateur d'identité)")
    else:
        print("    ❌ La signature invalide a été acceptée !")

if __name__ == "__main__":
    demo()