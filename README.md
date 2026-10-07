# D-HPPK KEM — Reference Implementation

C reference implementation of the D-HPPK IND-CCA2 Key Encapsulation
Mechanism described in:

> **D-HPPK KEM: A Defactorized Homomorphic Polynomial Public Key
> Encapsulation Mechanism for IND-CCA2 Security**
> Randy Kuang, Quantropi Inc.
> Manuscript ID: jcp-4541440
> *Journal of Cybersecurity and Privacy* (MDPI)

---

## Overview

This repository contains a **feasibility implementation** of the
D-HPPK KEM in C, using GMP for large-integer arithmetic and OpenSSL
for SHA-256. It supports the three NIST security levels I, III, and V.

The implementation demonstrates two things:

1. The construction of the manuscript's Section 3 is realizable in a
   straightforward C program.
2. The public key, secret key, and ciphertext sizes reported in
   Table 3 of the manuscript are achieved in practice.

It is **not** a production library, **not** constant-time, and **not**
a performance benchmark. The manuscript's performance claims rest on
the algorithm-independent operation counts (Table 4) and on the key
and ciphertext sizes (Table 3), both of which are independent of the
implementation platform.

The implementation exercises only the **honest encapsulation and
decapsulation path**. It is designed to verify the correctness of key
agreement and the byte-size claims, not to serve as a
security-complete reference that resists adversarial decapsulation
queries. See [Scope and Simplifications](#scope-and-simplifications)
for details. **The manuscript's security claims do not depend on this
code.**

---

## Scope and Simplifications

Several simplifications are made for clarity. None affects the
correctness of the key agreement or the size claims.

- **Degenerate-pair rejection.** The manuscript's Section 3.3 states
  that key generation rejects polynomial pairs satisfying
  `f1·h0 − f0·h1 = 0`. This event has probability at most `1/p`,
  which is below `2⁻¹²⁸` at Level I. The reference implementation does
  not test for it. The omission is a negligible-probability
  correctness edge case, not a security concern: if such a pair were
  ever sampled, the Möbius map would be constant and the honest user
  would simply regenerate the key pair.

- **Rejection Classes 3 and 5.** The feasibility implementation
  enforces only Classes 1 and 2 of the manuscript's rejection set
  (Sections 3.4 and 4.8). Classes 3 (integer scalar multiples) and 5
  (non-unit components) are not exercised by the honest encapsulation
  path, and their omission does not affect the size verification or
  the key agreement. A deployment-grade implementation should include
  all five classes as specified in the manuscript. Class 4
  (challenge-component reuse) is enforced by the IND-CCA2 game rather
  than by the decapsulation algorithm, so it is deliberately absent
  from the code. The manuscript's Class 5 footnote explains that an
  implementation may narrow Class 5 to `cp ≡ 0 (mod S1)` or
  `cq ≡ 0 (mod S2)`; this demo implements neither the general nor the
  narrowed form.

- **Primality of fixed primes.** The implementation uses the fixed
  primes `p = 2^l − δ` with `δ ∈ {159, 237, 189}` for
  `l ∈ {128, 192, 256}`. These values are known primes and are trusted
  at runtime without verification.

- **Cycle counts.** The performance figures reported by the program
  are derived from wall-clock time multiplied by the nominal base
  clock frequency (1.7 GHz). They are intended as a rough indication
  and are not obtained from hardware counters. The manuscript's
  performance claims do not depend on these figures.

- **Constant-time behavior.** The implementation uses GMP and is not
  constant-time. The manuscript states this limitation in Section 5.4
  and outlines a hardening roadmap for a production implementation.

---

## Build and Run

### Requirements

- A C compiler (GCC or Clang)
- [GMP](https://gmplib.org/) (GNU Multiple Precision Arithmetic Library)
- [OpenSSL](https://www.openssl.org/) (for SHA-256)

### Compile

```bash
gcc -O2 -march=native -Wno-deprecated-declarations \
    -o d_hppk_kem d_hppk_kem.c -lgmp -lssl -lcrypto

### Run
./d_hppk_kem -l I      # NIST Level I   (p: 128-bit)
./d_hppk_kem -l III    # NIST Level III (p: 192-bit)
./d_hppk_kem -l V      # NIST Level V   (p: 256-bit)
