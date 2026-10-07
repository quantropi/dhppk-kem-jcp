/**
 * D-HPPK KEM – C implementation using GMP and OpenSSL
 * Supports NIST security levels I, III, V
 *
 * This file implements the full IND-CCA2 KEM of §3.4 of the
 * manuscript: double encryption with a consistency check, and
 * the rejection-set handling for Classes 1 and 2 of §4.6.
 *
 * Compile:
 *   gcc -O2 -march=native -Wno-deprecated-declarations \
 *       -o d_hppk_kem d_hppk_kem.c -lgmp -lssl -lcrypto
 *
 * Usage:
 *   ./d_hppk_kem -l I
 *   ./d_hppk_kem -l III
 *   ./d_hppk_kem -l V
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>
#include <gmp.h>
#include <openssl/evp.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* ================= Security Levels ================= */
typedef enum {
    LEVEL_I,
    LEVEL_III,
    LEVEL_V
} SecurityLevel;

/* ================= Fixed Primes ================= */
static void fixed_prime(SecurityLevel level, mpz_t p) {
    switch (level) {
        case LEVEL_I:
            mpz_set_ui(p, 1);
            mpz_mul_2exp(p, p, 128);
            mpz_sub_ui(p, p, 159);
            break;
        case LEVEL_III:
            mpz_set_ui(p, 1);
            mpz_mul_2exp(p, p, 192);
            mpz_sub_ui(p, p, 237);
            break;
        case LEVEL_V:
            mpz_set_ui(p, 1);
            mpz_mul_2exp(p, p, 256);
            mpz_sub_ui(p, p, 189);
            break;
        default:
            fprintf(stderr, "Unknown security level\n");
            exit(1);
    }
}

/* ================= Key Structures ================= */
typedef struct {
    mpz_t **P;       /* 3 x m */
    mpz_t **Q;       /* 3 x m */
    mpz_t *d;        /* length m, d[m-1] = 1 */
} PublicKey;

typedef struct {
    mpz_t f0, f1, h0, h1;
    mpz_t S1, S2;
    mpz_t R1inv, R2inv;
} PrivateKey;

typedef struct {
    mpz_t cp, cq;
} CipherText;

typedef struct {
    PublicKey pk;
    PrivateKey sk;
} KeyPair;

/* CCA2 CHANGE: the encapsulation now holds two ciphertexts. */
typedef struct {
    CipherText ct1;
    CipherText ct2;
    uint8_t key[32];
} Encapsulation;

/* ================= Global Parameters ================= */
static SecurityLevel current_level;
static mpz_t p;          /* prime modulus */
static int l;            /* bit-length of p */
static int m;            /* noise dimension (default 3) */
static int L;            /* hidden modulus bit-length: 2*l+8 */

/* random state */
static gmp_randstate_t rand_state;

/* ================= Function Prototypes ================= */
static void init_rand(void);
static void rand_mpz(mpz_t rop, mpz_t bound);
static void rand_mpz_bits(mpz_t rop, int bits);
static void random_invertible_modulus(mpz_t val, mpz_t modulus);
static void sha256(const uint8_t *data, size_t len, uint8_t *out);
static void kdf_cca2(mpz_t x, CipherText *ct1, CipherText *ct2, uint8_t *out);
static void keyGen(KeyPair *kp);
static void encrypt(PublicKey *pk, mpz_t x, CipherText *ct);
static int  decrypt(PrivateKey *sk, CipherText *ct, mpz_t x);
static void encapsulate(PublicKey *pk, Encapsulation *enc);
static int  decapsulate(PrivateKey *sk, Encapsulation *enc, uint8_t *key);
static void print_sizes(void);
static void performance_test(int repetitions);
static void free_keypair(KeyPair *kp);
static void free_encapsulation(Encapsulation *enc);

/* ================= Utilities ================= */
static void init_rand(void) {
    unsigned long seed[8];
    int use_urandom = 0;
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        if (fread(seed, sizeof(seed), 1, urandom) == 1)
            use_urandom = 1;
        fclose(urandom);
    }
    if (!use_urandom) {
        srand((unsigned int)time(NULL));
        for (int i = 0; i < 8; i++) {
            seed[i] = (unsigned long)rand() ^ (unsigned long)clock();
#ifdef _WIN32
            seed[i] ^= (unsigned long)GetCurrentProcessId();
#else
            seed[i] ^= (unsigned long)getpid();
#endif
        }
    }
    gmp_randinit_default(rand_state);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, sizeof(seed), 1, sizeof(seed[0]), 0, 0, seed);
    gmp_randseed(rand_state, tmp);
    mpz_clear(tmp);
}

static void rand_mpz(mpz_t rop, mpz_t bound) {
    mpz_urandomm(rop, rand_state, bound);
}

static void rand_mpz_bits(mpz_t rop, int bits) {
    mpz_urandomb(rop, rand_state, bits);
    mpz_setbit(rop, bits - 1);
}

static void random_invertible_modulus(mpz_t val, mpz_t modulus) {
    mpz_t gcd;
    mpz_init(gcd);
    do {
        mpz_urandomm(val, rand_state, modulus);
    } while (mpz_cmp_ui(val, 0) == 0 ||
             (mpz_gcd(gcd, val, modulus), mpz_cmp_ui(gcd, 1) != 0));
    mpz_clear(gcd);
}

static void sha256(const uint8_t *data, size_t len, uint8_t *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

/* CCA2 CHANGE: hash x || C^(1) || C^(2). */
static void kdf_cca2(mpz_t x, CipherText *ct1, CipherText *ct2, uint8_t *out) {
    size_t xlen  = (mpz_sizeinbase(x, 2) + 7) / 8;
    size_t cp1_l = (mpz_sizeinbase(ct1->cp, 2) + 7) / 8;
    size_t cq1_l = (mpz_sizeinbase(ct1->cq, 2) + 7) / 8;
    size_t cp2_l = (mpz_sizeinbase(ct2->cp, 2) + 7) / 8;
    size_t cq2_l = (mpz_sizeinbase(ct2->cq, 2) + 7) / 8;

    size_t total = xlen + cp1_l + cq1_l + cp2_l + cq2_l;
    uint8_t *buf = malloc(total);

    uint8_t *wp = buf;
    size_t s;
    s = xlen;  mpz_export(wp, &s, 1, 1, 1, 0, x);          wp += s;
    s = cp1_l; mpz_export(wp, &s, 1, 1, 1, 0, ct1->cp);    wp += s;
    s = cq1_l; mpz_export(wp, &s, 1, 1, 1, 0, ct1->cq);    wp += s;
    s = cp2_l; mpz_export(wp, &s, 1, 1, 1, 0, ct2->cp);    wp += s;
    s = cq2_l; mpz_export(wp, &s, 1, 1, 1, 0, ct2->cq);

    sha256(buf, total, out);
    free(buf);
}

/* ================= Key Generation (unchanged) ================= */
static void keyGen(KeyPair *kp) {
    mpz_t f0, f1, h0, h1;
    mpz_init(f0); mpz_init(f1); mpz_init(h0); mpz_init(h1);
    rand_mpz(f0, p);
    do { rand_mpz(f1, p); } while (mpz_cmp_ui(f1, 0) == 0);
    rand_mpz(h0, p);
    do { rand_mpz(h1, p); } while (mpz_cmp_ui(h1, 0) == 0);

    mpz_t **b = malloc(2 * sizeof(mpz_t*));
    for (int i = 0; i < 2; i++) {
        b[i] = malloc(m * sizeof(mpz_t));
        for (int j = 0; j < m; j++) mpz_init(b[i][j]);
    }
    for (int j = 0; j < m; j++) {
        rand_mpz(b[0][j], p);
        rand_mpz(b[1][j], p);
    }

    mpz_t **pMat = malloc(3 * sizeof(mpz_t*));
    mpz_t **qMat = malloc(3 * sizeof(mpz_t*));
    for (int i = 0; i < 3; i++) {
        pMat[i] = malloc(m * sizeof(mpz_t));
        qMat[i] = malloc(m * sizeof(mpz_t));
        for (int j = 0; j < m; j++) {
            mpz_init(pMat[i][j]);
            mpz_init(qMat[i][j]);
        }
    }
    mpz_t tmp1, tmp2;
    mpz_init(tmp1); mpz_init(tmp2);
    for (int j = 0; j < m; j++) {
        mpz_mul(pMat[0][j], f0, b[0][j]); mpz_mod(pMat[0][j], pMat[0][j], p);
        mpz_mul(tmp1, f1, b[0][j]); mpz_mul(tmp2, f0, b[1][j]); mpz_add(tmp1, tmp1, tmp2);
        mpz_mod(pMat[1][j], tmp1, p);
        mpz_mul(pMat[2][j], f1, b[1][j]); mpz_mod(pMat[2][j], pMat[2][j], p);

        mpz_mul(qMat[0][j], h0, b[0][j]); mpz_mod(qMat[0][j], qMat[0][j], p);
        mpz_mul(tmp1, h1, b[0][j]); mpz_mul(tmp2, h0, b[1][j]); mpz_add(tmp1, tmp1, tmp2);
        mpz_mod(qMat[1][j], tmp1, p);
        mpz_mul(qMat[2][j], h1, b[1][j]); mpz_mod(qMat[2][j], qMat[2][j], p);
    }

    mpz_t *cp = malloc(3 * sizeof(mpz_t));
    mpz_t *cq = malloc(3 * sizeof(mpz_t));
    mpz_t *d  = malloc(m * sizeof(mpz_t));
    for (int i = 0; i < 3; i++) {
        mpz_init(cp[i]); rand_mpz(cp[i], p);
        mpz_init(cq[i]); rand_mpz(cq[i], p);
    }
    for (int j = 0; j < m-1; j++) {
        mpz_init(d[j]); rand_mpz(d[j], p);
    }
    mpz_init_set_ui(d[m-1], 1);

    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < m; j++) {
            mpz_mul(tmp1, cp[i], d[j]); mpz_add(pMat[i][j], pMat[i][j], tmp1);
            mpz_mod(pMat[i][j], pMat[i][j], p);
            mpz_mul(tmp1, cq[i], d[j]); mpz_add(qMat[i][j], qMat[i][j], tmp1);
            mpz_mod(qMat[i][j], qMat[i][j], p);
        }
    }

    mpz_t minS, S1, S2;
    mpz_init(minS); mpz_init(S1); mpz_init(S2);
    mpz_mul(minS, p, p); mpz_mul_ui(minS, minS, 9);
    do { rand_mpz_bits(S1, L); } while (mpz_cmp(S1, minS) <= 0);
    do { rand_mpz_bits(S2, L); } while (mpz_cmp(S2, minS) <= 0);

    mpz_t R1, R2, R1inv, R2inv;
    mpz_init(R1); mpz_init(R2); mpz_init(R1inv); mpz_init(R2inv);
    do { random_invertible_modulus(R1, S1); } while (mpz_cmp_ui(R1, 0) == 0);
    do { random_invertible_modulus(R2, S2); } while (mpz_cmp_ui(R2, 0) == 0);
    mpz_invert(R1inv, R1, S1);
    mpz_invert(R2inv, R2, S2);

    mpz_t **P = malloc(3 * sizeof(mpz_t*));
    mpz_t **Q = malloc(3 * sizeof(mpz_t*));
    for (int i = 0; i < 3; i++) {
        P[i] = malloc(m * sizeof(mpz_t));
        Q[i] = malloc(m * sizeof(mpz_t));
        for (int j = 0; j < m; j++) {
            mpz_init(P[i][j]);
            mpz_init(Q[i][j]);
            mpz_mul(P[i][j], pMat[i][j], R1); mpz_mod(P[i][j], P[i][j], S1);
            mpz_mul(Q[i][j], qMat[i][j], R2); mpz_mod(Q[i][j], Q[i][j], S2);
        }
    }

    kp->pk.P = P;
    kp->pk.Q = Q;
    kp->pk.d = d;

    mpz_init_set(kp->sk.f0, f0);
    mpz_init_set(kp->sk.f1, f1);
    mpz_init_set(kp->sk.h0, h0);
    mpz_init_set(kp->sk.h1, h1);
    mpz_init_set(kp->sk.S1, S1);
    mpz_init_set(kp->sk.S2, S2);
    mpz_init_set(kp->sk.R1inv, R1inv);
    mpz_init_set(kp->sk.R2inv, R2inv);

    mpz_clear(tmp1); mpz_clear(tmp2);
    mpz_clear(minS); mpz_clear(S1); mpz_clear(S2);
    mpz_clear(R1); mpz_clear(R2); mpz_clear(R1inv); mpz_clear(R2inv);
    mpz_clear(f0); mpz_clear(f1); mpz_clear(h0); mpz_clear(h1);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < m; j++) mpz_clear(b[i][j]);
        free(b[i]);
    }
    free(b);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < m; j++) { mpz_clear(pMat[i][j]); mpz_clear(qMat[i][j]); }
        free(pMat[i]); free(qMat[i]);
    }
    free(pMat); free(qMat);
    for (int i = 0; i < 3; i++) { mpz_clear(cp[i]); mpz_clear(cq[i]); }
    free(cp); free(cq);
}

/* ================= Encryption (unchanged) ================= */
static void encrypt(PublicKey *pk, mpz_t x, CipherText *ct) {
    mpz_t *u = malloc(m * sizeof(mpz_t));
    mpz_t sum;
    mpz_init(sum);
    for (int j = 0; j < m-1; j++) {
        mpz_init(u[j]);
        rand_mpz(u[j], p);
        mpz_addmul(sum, pk->d[j], u[j]);
        mpz_mod(sum, sum, p);
    }
    mpz_init(u[m-1]);
    mpz_neg(u[m-1], sum);
    mpz_mod(u[m-1], u[m-1], p);

    mpz_t xp[3];
    mpz_init_set_ui(xp[0], 1);
    mpz_init_set(xp[1], x);
    mpz_init(xp[2]);
    mpz_mul(xp[2], x, x);
    mpz_mod(xp[2], xp[2], p);

    mpz_init_set_ui(ct->cp, 0);
    mpz_init_set_ui(ct->cq, 0);
    mpz_t term;
    mpz_init(term);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < m; j++) {
            mpz_mul(term, xp[i], u[j]);
            mpz_mod(term, term, p);
            mpz_addmul(ct->cp, pk->P[i][j], term);
            mpz_addmul(ct->cq, pk->Q[i][j], term);
        }
    }
    mpz_clear(term);
    for (int i = 0; i < 3; i++) mpz_clear(xp[i]);
    for (int j = 0; j < m; j++) mpz_clear(u[j]);
    free(u);
    mpz_clear(sum);
}

/* ================= Decryption ================= */
/* CCA2 CHANGE: returns 0 on success, -1 on failure (was: exit(1)). */
static int decrypt(PrivateKey *sk, CipherText *ct, mpz_t x) {
    mpz_t a, b, a_mod, b_mod, k, num, den;
    mpz_init(a); mpz_init(b); mpz_init(a_mod); mpz_init(b_mod);
    mpz_init(k); mpz_init(num); mpz_init(den);

    mpz_mod(a, ct->cp, sk->S1);
    mpz_mul(a, sk->R1inv, a);
    mpz_mod(a, a, sk->S1);
    mpz_mod(b, ct->cq, sk->S2);
    mpz_mul(b, sk->R2inv, b);
    mpz_mod(b, b, sk->S2);

    mpz_mod(a_mod, a, p);
    mpz_mod(b_mod, b, p);
    if (mpz_cmp_ui(b_mod, 0) == 0) {
        mpz_clear(a); mpz_clear(b); mpz_clear(a_mod); mpz_clear(b_mod);
        mpz_clear(k); mpz_clear(num); mpz_clear(den);
        return -1;
    }
    mpz_invert(b_mod, b_mod, p);
    mpz_mul(k, a_mod, b_mod);
    mpz_mod(k, k, p);

    mpz_mul(num, k, sk->h0);
    mpz_sub(num, sk->f0, num);
    mpz_mod(num, num, p);
    mpz_mul(den, k, sk->h1);
    mpz_sub(den, den, sk->f1);
    mpz_mod(den, den, p);
    if (mpz_cmp_ui(den, 0) == 0) {
        mpz_clear(a); mpz_clear(b); mpz_clear(a_mod); mpz_clear(b_mod);
        mpz_clear(k); mpz_clear(num); mpz_clear(den);
        return -1;
    }
    mpz_invert(den, den, p);
    mpz_mul(x, num, den);
    mpz_mod(x, x, p);

    mpz_clear(a); mpz_clear(b); mpz_clear(a_mod); mpz_clear(b_mod);
    mpz_clear(k); mpz_clear(num); mpz_clear(den);
    return 0;
}

/* ================= KEM Encapsulation (CCA2) ================= */
/* CCA2 CHANGE: two independent encryptions under the same x,
   and K = H(x || C^(1) || C^(2)). */
static void encapsulate(PublicKey *pk, Encapsulation *enc) {
    mpz_t x;
    mpz_init(x);
    rand_mpz(x, p);
    encrypt(pk, x, &enc->ct1);
    encrypt(pk, x, &enc->ct2);
    kdf_cca2(x, &enc->ct1, &enc->ct2, enc->key);
    mpz_clear(x);
}

/* ================= KEM Decapsulation (CCA2) ================= */
/* CCA2 CHANGE: full IND-CCA2 decapsulation with rejection-set
   handling for Classes 1 and 2 of §4.6, two decryptions, and the
   consistency check of §3.4. Returns 0 on success (key written to
   `key`), -1 on rejection. */
static int decapsulate(PrivateKey *sk, Encapsulation *enc, uint8_t *key) {
    /* Class 1: reject if C^(1) == C^(2). In production this is a
       constant-time comparison; here we use GMP's comparison. */
    if (mpz_cmp(enc->ct1.cp, enc->ct2.cp) == 0 &&
        mpz_cmp(enc->ct1.cq, enc->ct2.cq) == 0) {
        return -1;
    }

    /* Class 2: reject residue-preserving shifts, i.e. if
       c_p^(1) ≡ c_p^(2) (mod S_1) and c_q^(1) ≡ c_q^(2) (mod S_2). */
    mpz_t r1a, r1b, r2a, r2b;
    mpz_init(r1a); mpz_init(r1b); mpz_init(r2a); mpz_init(r2b);
    mpz_mod(r1a, enc->ct1.cp, sk->S1);
    mpz_mod(r1b, enc->ct2.cp, sk->S1);
    mpz_mod(r2a, enc->ct1.cq, sk->S2);
    mpz_mod(r2b, enc->ct2.cq, sk->S2);
    int class2 = (mpz_cmp(r1a, r1b) == 0 && mpz_cmp(r2a, r2b) == 0);
    mpz_clear(r1a); mpz_clear(r1b); mpz_clear(r2a); mpz_clear(r2b);
    if (class2) return -1;

    /* Decrypt both components. */
    mpz_t x1, x2;
    mpz_init(x1); mpz_init(x2);
    if (decrypt(sk, &enc->ct1, x1) != 0) {
        mpz_clear(x1); mpz_clear(x2);
        return -1;
    }
    if (decrypt(sk, &enc->ct2, x2) != 0) {
        mpz_clear(x1); mpz_clear(x2);
        return -1;
    }

    /* Consistency check: x_1 == x_2. */
    if (mpz_cmp(x1, x2) != 0) {
        mpz_clear(x1); mpz_clear(x2);
        return -1;
    }

    /* K = H(x_1 || C^(1) || C^(2)). */
    kdf_cca2(x1, &enc->ct1, &enc->ct2, key);
    mpz_clear(x1); mpz_clear(x2);
    return 0;
}

/* ================= Helper: free routines ================= */
static void free_keypair(KeyPair *kp) {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < m; j++) {
            mpz_clear(kp->pk.P[i][j]);
            mpz_clear(kp->pk.Q[i][j]);
        }
        free(kp->pk.P[i]); free(kp->pk.Q[i]);
    }
    free(kp->pk.P); free(kp->pk.Q);
    for (int j = 0; j < m; j++) mpz_clear(kp->pk.d[j]);
    free(kp->pk.d);
    mpz_clear(kp->sk.f0); mpz_clear(kp->sk.f1);
    mpz_clear(kp->sk.h0); mpz_clear(kp->sk.h1);
    mpz_clear(kp->sk.S1); mpz_clear(kp->sk.S2);
    mpz_clear(kp->sk.R1inv); mpz_clear(kp->sk.R2inv);
}

static void free_encapsulation(Encapsulation *enc) {
    mpz_clear(enc->ct1.cp); mpz_clear(enc->ct1.cq);
    mpz_clear(enc->ct2.cp); mpz_clear(enc->ct2.cq);
}

/* ================= Size Verification ================= */
static void print_sizes(void) {
    KeyPair kp;
    Encapsulation enc;
    keyGen(&kp);
    encapsulate(&kp.pk, &enc);

    size_t pk_bytes_actual = 0;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < m; j++) {
            pk_bytes_actual += (mpz_sizeinbase(kp.pk.P[i][j], 2) + 7) / 8;
            pk_bytes_actual += (mpz_sizeinbase(kp.pk.Q[i][j], 2) + 7) / 8;
        }
    for (int j = 0; j < m; j++)
        pk_bytes_actual += (mpz_sizeinbase(kp.pk.d[j], 2) + 7) / 8;

    size_t sk_bytes_actual = 0;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.f0, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.f1, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.h0, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.h1, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.S1, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.S2, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.R1inv, 2) + 7) / 8;
    sk_bytes_actual += (mpz_sizeinbase(kp.sk.R2inv, 2) + 7) / 8;

    /* CCA2 CHANGE: measure the actual two-ciphertext size. */
    size_t cp1 = (mpz_sizeinbase(enc.ct1.cp, 2) + 7) / 8;
    size_t cq1 = (mpz_sizeinbase(enc.ct1.cq, 2) + 7) / 8;
    size_t cp2 = (mpz_sizeinbase(enc.ct2.cp, 2) + 7) / 8;
    size_t cq2 = (mpz_sizeinbase(enc.ct2.cq, 2) + 7) / 8;
    size_t cpa_bytes_actual = cp1 + cq1;
    size_t cca_bytes_actual = cp1 + cq1 + cp2 + cq2;

    int pk_bytes_theo, sk_bytes_theo, cpa_bytes_theo, cca_bytes_theo;
    switch (current_level) {
        case LEVEL_I:
            pk_bytes_theo = 626; sk_bytes_theo = 196;
            cpa_bytes_theo = 100; cca_bytes_theo = 200;
            break;
        case LEVEL_III:
            pk_bytes_theo = 930; sk_bytes_theo = 292;
            cpa_bytes_theo = 148; cca_bytes_theo = 296;
            break;
        default:
            pk_bytes_theo = 1234; sk_bytes_theo = 388;
            cpa_bytes_theo = 196; cca_bytes_theo = 392;
            break;
    }

    const char *level_str;
    switch (current_level) {
        case LEVEL_I:   level_str = "I"; break;
        case LEVEL_III: level_str = "III"; break;
        default:        level_str = "V"; break;
    }
    printf("=== D-HPPK KEM Size Verification (Level %s) ===\n", level_str);
    printf("Public key bytes (actual): %zu\n", pk_bytes_actual);
    printf("Theoretical: %d bytes\n", pk_bytes_theo);
    printf("Secret key bytes (actual): %zu\n", sk_bytes_actual);
    printf("Theoretical: %d bytes\n", sk_bytes_theo);
    printf("CPA ciphertext bytes (actual): %zu\n", cpa_bytes_actual);
    printf("Theoretical: %d bytes\n", cpa_bytes_theo);
    printf("CCA ciphertext bytes (actual): %zu\n", cca_bytes_actual);
    printf("Theoretical: %d bytes\n", cca_bytes_theo);

    free_encapsulation(&enc);
    free_keypair(&kp);
}

/* ================= Performance Test ================= */
static void performance_test(int repetitions) {
    const char *level_str;
    switch (current_level) {
        case LEVEL_I:   level_str = "I"; break;
        case LEVEL_III: level_str = "III"; break;
        default:        level_str = "V"; break;
    }
    printf("\n===== D-HPPK KEM Performance Test (Level %s) =====\n", level_str);
    struct timespec start, end;
    long total_keygen_ns = 0, total_encap_ns = 0, total_decap_ns = 0;

    /* Warm-up */
    for (int i = 0; i < 1000; i++) {
        KeyPair kp;
        Encapsulation enc;
        keyGen(&kp);
        encapsulate(&kp.pk, &enc);
        uint8_t key_recovered[32];
        decapsulate(&kp.sk, &enc, key_recovered);
        free_encapsulation(&enc);
        free_keypair(&kp);
    }

    for (int i = 0; i < repetitions; i++) {
        KeyPair kp;
        Encapsulation enc;

        clock_gettime(CLOCK_MONOTONIC, &start);
        keyGen(&kp);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_keygen_ns += (end.tv_sec - start.tv_sec) * 1000000000L
                         + (end.tv_nsec - start.tv_nsec);

        clock_gettime(CLOCK_MONOTONIC, &start);
        encapsulate(&kp.pk, &enc);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_encap_ns += (end.tv_sec - start.tv_sec) * 1000000000L
                        + (end.tv_nsec - start.tv_nsec);

        clock_gettime(CLOCK_MONOTONIC, &start);
        uint8_t key_recovered[32];
        int rv = decapsulate(&kp.sk, &enc, key_recovered);
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_decap_ns += (end.tv_sec - start.tv_sec) * 1000000000L
                        + (end.tv_nsec - start.tv_nsec);

        if (rv != 0 || memcmp(enc.key, key_recovered, 32) != 0) {
            fprintf(stderr, "Key mismatch at iteration %d\n", i);
            exit(1);
        }

        free_encapsulation(&enc);
        free_keypair(&kp);
    }

    double avg_keygen_ms = total_keygen_ns / 1e6 / repetitions;
    double avg_encap_ms  = total_encap_ns  / 1e6 / repetitions;
    double avg_decap_ms  = total_decap_ns  / 1e6 / repetitions;
    long cpu_freq_hz = 1700000000L; /* 1.7 GHz */
    printf("Repetitions: %d\n", repetitions);
    printf("Average KeyGen time: %.3f ms, ~%.0f cycles\n",
           avg_keygen_ms, avg_keygen_ms * cpu_freq_hz / 1000.0);
    printf("Average Encapsulation time: %.3f ms, ~%.0f cycles\n",
           avg_encap_ms, avg_encap_ms * cpu_freq_hz / 1000.0);
    printf("Average Decapsulation time: %.3f ms, ~%.0f cycles\n",
           avg_decap_ms, avg_decap_ms * cpu_freq_hz / 1000.0);
}

/* ================= Main ================= */
int main(int argc, char **argv) {
    int opt;
    SecurityLevel level = LEVEL_V;
    while ((opt = getopt(argc, argv, "l:")) != -1) {
        if (opt == 'l') {
            if      (strcmp(optarg, "I")   == 0) level = LEVEL_I;
            else if (strcmp(optarg, "III") == 0) level = LEVEL_III;
            else if (strcmp(optarg, "V")   == 0) level = LEVEL_V;
            else {
                fprintf(stderr, "Invalid level: %s\n", optarg);
                return 1;
            }
        }
    }

    current_level = level;
    m = 3;
    mpz_init(p);
    fixed_prime(current_level, p);
    l = mpz_sizeinbase(p, 2);
    L = 2 * l + 8;

    init_rand();

    KeyPair kp;
    keyGen(&kp);

    Encapsulation enc;
    encapsulate(&kp.pk, &enc);

    uint8_t key_recovered[32];
    int rv = decapsulate(&kp.sk, &enc, key_recovered);
    if (rv != 0) {
        fprintf(stderr, "Decapsulation failed\n");
        return 1;
    }

    printf("Encapsulated key (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", enc.key[i]);
    printf("\nDecapsulated key (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", key_recovered[i]);
    printf("\nKey agreement : %s\n",
           memcmp(enc.key, key_recovered, 32) == 0 ? "true" : "false");

    print_sizes();
    performance_test(10000);

    free_encapsulation(&enc);
    free_keypair(&kp);
    mpz_clear(p);
    gmp_randclear(rand_state);
    return 0;
}
