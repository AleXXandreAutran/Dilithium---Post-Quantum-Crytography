# Simplified Python Implementation of Dilithium / ML-DSA

This project contains a pedagogical Python implementation inspired by the post-quantum signature scheme Dilithium, now standardized as ML-DSA.

The goal of this code is to illustrate the main ideas of the scheme:
- public matrix generation;
- sampling of small secret vectors;
- computation of the public vector;
- signature generation;
- signature verification using a hashed challenge.

## Available Parameters

The code supports several security levels inspired by ML-DSA:

| Security level | k | l | η |
|---|---:|---:|---:|
| ML-DSA-44 | 4 | 4 | 2 |
| ML-DSA-65 | 6 | 5 | 2 |
| ML-DSA-87 | 8 | 7 | 2 |

## General Workflow

The program follows these main steps:

1. Generation of a public matrix used in the computations.
2. Generation of small secret vectors.
3. Computation of the public key from the matrix and the secret vectors.
4. Signing of a message using the secret key.
5. Verification of the signature using the public key.

The hashing functions are directly imported from the corresponding Python libraries.

## Usage

Clone the repository:

```bash
git clone https://gitlab.inria.fr/guillevi/stage-l3-alexandre-autran
