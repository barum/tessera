/*
 * tessera_seal_ext.c — CPython extension binding for the TesseraSeal C reference.
 *
 * Mirrors the API surface of tessera-seal/python/tessera_seal.py but routes
 * every call into the C reference (../c/tessera_seal.c +
 * ../../common/c/hkdf_sha3.c) for an order-of-magnitude speedup over the
 * pure-Python kyber-py path.
 *
 * Functions exposed:
 *   generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes)
 *   generate_keypair_hybrid() -> (sk_bytes, pk_bytes)            # suite 0x06
 *   generate_keypair_hybrid_from_seed(seed96) -> (sk_bytes, pk_bytes)
 *   encrypt(pt, pk_bytes, suite=0x01, ad=b"", ts_ms=None, counter=0) -> envelope
 *   decrypt(envelope, sk_bytes, expected_ad=b"") -> plaintext
 *   peek_header(envelope) -> dict
 *   peek_ad(envelope) -> bytes   (UNAUTHENTICATED until decrypt; TSEAL-00047)
 *   validate(envelope) -> bool
 *   validate_min_timestamp(envelope, min_ms) -> bool
 *   set_now_ms_for_testing(value)   # value=-1 to clear
 *
 * Sizes match tessera_seal.h. Errors raise TesseraSealError (sub-classed per
 * status code: UnknownVariant, UnknownSuite, InvalidLength, DecryptionError,
 * BadKey).
 *
 * Raw key bytes carry no suite tag in this binding, so decrypt() adopts the
 * suite from the envelope header (structural peek) before calling the C
 * library — see py_decrypt (TSEAL-00036).
 *
 * Hybrid suite 0x06 (TSEAL-00034): the same encrypt()/decrypt() entry points
 * route to the C library's tessera_seal_*_hybrid functions when the recipient
 * key (encrypt) or the envelope header (decrypt) is the 1600-byte hybrid pk /
 * 0x06 header. The 0x06 KEM_CT on the wire is 1600 B (ml_kem_ct 1568 ||
 * x25519_eph_pk 32). Hybrid private keys are 3200 B, hybrid public keys 1600 B;
 * suite is inferred from key length on encrypt and from the header on decrypt.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "tessera_seal.h"

static PyObject *TesseraSealError;
static PyObject *UnknownVariantError;
static PyObject *UnknownSuiteError;
static PyObject *InvalidLengthError;
static PyObject *DecryptionError;
static PyObject *BadKeyError;

static int raise_status(int rc, const char *where) {
    PyObject *exc = TesseraSealError;
    const char *msg = "internal error";
    switch (rc) {
        case TESSERA_SEAL_OK:                 return 0;
        case TESSERA_SEAL_E_INVALID_LEN:      exc = InvalidLengthError; msg = "invalid length"; break;
        case TESSERA_SEAL_E_UNKNOWN_VARIANT:  exc = UnknownVariantError; msg = "unknown variant byte"; break;
        case TESSERA_SEAL_E_UNKNOWN_SUITE:    exc = UnknownSuiteError; msg = "unknown suite byte"; break;
        case TESSERA_SEAL_E_DECRYPT_FAILED:   exc = DecryptionError; msg = "envelope failed authentication"; break;
        case TESSERA_SEAL_E_RNG:              msg = "CSPRNG failure"; break;
        case TESSERA_SEAL_E_BUF_TOO_SMALL:    msg = "output buffer too small"; break;
        case TESSERA_SEAL_E_BAD_KEY:          exc = BadKeyError; msg = "bad key (suite/key mismatch)"; break;
        default:                              msg = "unknown error"; break;
    }
    PyErr_Format(exc, "%s: %s (rc=%d)", where, msg, rc);
    return -1;
}

/* generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes) */
static PyObject *py_generate_keypair(PyObject *self, PyObject *args, PyObject *kwds) {
    (void)self;
    static char *kwlist[] = {"suite", NULL};
    unsigned char suite = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|b", kwlist, &suite)) return NULL;

    tessera_seal_priv_t priv = {0};
    tessera_seal_pub_t  pub = {0};
    int rc = tessera_seal_generate_keypair(suite, &priv, &pub);
    if (rc != TESSERA_SEAL_OK) { raise_status(rc, "generate_keypair"); return NULL; }
    PyObject *sk = PyBytes_FromStringAndSize((const char *)priv.sk, TESSERA_SEAL_MLKEM1024_SK_BYTES);
    PyObject *pk = PyBytes_FromStringAndSize((const char *)pub.pk, TESSERA_SEAL_MLKEM1024_PK_BYTES);
    tessera_seal_zeroize_priv(&priv);
    if (!sk || !pk) { Py_XDECREF(sk); Py_XDECREF(pk); return NULL; }
    return PyTuple_Pack(2, sk, pk);
}

/* generate_keypair_hybrid() -> (sk_bytes, pk_bytes)  (suite 0x06)
 *
 * sk = ML-KEM-1024 sk (3168) || X25519 scalar (32)   = 3200 B
 * pk = ML-KEM-1024 pk (1568) || X25519 pk (32)        = 1600 B
 * Both halves use the OS CSPRNG (no userspace PRNG). */
static PyObject *py_generate_keypair_hybrid(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    tessera_seal_priv_hybrid_t priv = {0};
    tessera_seal_pub_hybrid_t  pub = {0};
    int rc = tessera_seal_generate_keypair_hybrid(&priv, &pub);
    if (rc != TESSERA_SEAL_OK) { raise_status(rc, "generate_keypair_hybrid"); return NULL; }
    PyObject *sk = PyBytes_FromStringAndSize((const char *)priv.sk, TESSERA_SEAL_HYBRID_SK_BYTES);
    PyObject *pk = PyBytes_FromStringAndSize((const char *)pub.pk, TESSERA_SEAL_HYBRID_PK_BYTES);
    tessera_seal_zeroize_priv_hybrid(&priv);
    if (!sk || !pk) { Py_XDECREF(sk); Py_XDECREF(pk); return NULL; }
    return PyTuple_Pack(2, sk, pk);
}

/* generate_keypair_hybrid_from_seed(seed) -> (sk_bytes, pk_bytes)
 *
 * seed = ML-KEM-1024 seed (d || z, 64 B) || X25519 scalar (32 B) = 96 B,
 * matching the Python/Go/Rust ordering. */
static PyObject *py_generate_keypair_hybrid_from_seed(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer seed_buf;
    if (PyObject_GetBuffer(arg, &seed_buf, PyBUF_SIMPLE) != 0) return NULL;
    if (seed_buf.len != TESSERA_SEAL_HYBRID_SEED_BYTES) {
        PyBuffer_Release(&seed_buf);
        PyErr_Format(TesseraSealError, "hybrid seed must be %d bytes",
                     (int)TESSERA_SEAL_HYBRID_SEED_BYTES);
        return NULL;
    }
    tessera_seal_priv_hybrid_t priv = {0};
    tessera_seal_pub_hybrid_t  pub = {0};
    int rc = tessera_seal_generate_keypair_hybrid_from_seed(
        (const uint8_t *)seed_buf.buf, &priv, &pub);
    PyBuffer_Release(&seed_buf);
    if (rc != TESSERA_SEAL_OK) { raise_status(rc, "generate_keypair_hybrid_from_seed"); return NULL; }
    PyObject *sk = PyBytes_FromStringAndSize((const char *)priv.sk, TESSERA_SEAL_HYBRID_SK_BYTES);
    PyObject *pk = PyBytes_FromStringAndSize((const char *)pub.pk, TESSERA_SEAL_HYBRID_PK_BYTES);
    tessera_seal_zeroize_priv_hybrid(&priv);
    if (!sk || !pk) { Py_XDECREF(sk); Py_XDECREF(pk); return NULL; }
    return PyTuple_Pack(2, sk, pk);
}

/* encrypt(pt, pk_bytes, suite=0x01, ad=b"", ts_ms=None, counter=0) -> envelope */
static PyObject *py_encrypt(PyObject *self, PyObject *args, PyObject *kwds) {
    (void)self;
    static char *kwlist[] = {
        "pt", "pk_bytes", "suite", "ad", "ts_ms", "counter", NULL
    };
    Py_buffer pt_buf;
    Py_buffer pk_buf;
    Py_buffer ad_buf = {0};
    unsigned char suite = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM;
    PyObject *ts_obj = Py_None;
    unsigned short counter = 0;
    int ad_given = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*y*|by*OH", kwlist,
                                     &pt_buf, &pk_buf, &suite, &ad_buf, &ts_obj, &counter)) {
        return NULL;
    }
    ad_given = ad_buf.buf != NULL;

    /* Hybrid suite 0x06 routes through tessera_seal_encrypt_hybrid with a
     * 1600-byte recipient pk (ml_kem_pk 1568 || x25519_pk 32). The suite is
     * implied by the hybrid key length, but we also require the caller to
     * request 0x06 explicitly so a 1600-byte pk passed under a non-hybrid
     * suite is a hard error rather than a silent reinterpretation. */
    int is_hybrid = (suite == TESSERA_SEAL_SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    size_t want_pk = is_hybrid ? (size_t) TESSERA_SEAL_HYBRID_PK_BYTES
                               : (size_t) TESSERA_SEAL_MLKEM1024_PK_BYTES;
    if ((size_t) pk_buf.len != want_pk) {
        PyBuffer_Release(&pt_buf);
        PyBuffer_Release(&pk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        PyErr_Format(TesseraSealError, "pk must be %zu bytes", want_pk);
        return NULL;
    }
    uint64_t ts_ms = UINT64_MAX;
    if (ts_obj != Py_None) {
        ts_ms = (uint64_t) PyLong_AsUnsignedLongLong(ts_obj);
        if (PyErr_Occurred()) {
            PyBuffer_Release(&pt_buf);
            PyBuffer_Release(&pk_buf);
            if (ad_given) PyBuffer_Release(&ad_buf);
            return NULL;
        }
    }

    size_t out_cap = is_hybrid
        ? tessera_seal_encrypt_hybrid_output_size((size_t) pt_buf.len, (size_t) (ad_given ? ad_buf.len : 0))
        : tessera_seal_encrypt_output_size((size_t) pt_buf.len, (size_t) (ad_given ? ad_buf.len : 0));
    PyObject *out_obj = PyBytes_FromStringAndSize(NULL, (Py_ssize_t) out_cap);
    if (!out_obj) {
        PyBuffer_Release(&pt_buf);
        PyBuffer_Release(&pk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        return NULL;
    }
    size_t out_len = out_cap;
    int rc;
    if (is_hybrid) {
        tessera_seal_pub_hybrid_t pub;
        pub.suite = TESSERA_SEAL_SUITE_HYBRID_X25519_MLKEM1024_AESGCM;
        memcpy(pub.pk, pk_buf.buf, TESSERA_SEAL_HYBRID_PK_BYTES);
        rc = tessera_seal_encrypt_hybrid(
            (const uint8_t *) pt_buf.buf, (size_t) pt_buf.len,
            &pub,
            ad_given ? (const uint8_t *) ad_buf.buf : NULL,
            ad_given ? (size_t) ad_buf.len : 0,
            ts_ms, counter,
            (uint8_t *) PyBytes_AS_STRING(out_obj), out_cap, &out_len);
    } else {
        tessera_seal_pub_t pub;
        /* Note: the binding takes raw pk bytes that carry no suite tag, so
         * pub.suite is set from the requested suite — which makes the C
         * library's pub->suite != suite consistency check vacuous through this
         * binding. Suite validity itself (unknown suite byte) is still
         * enforced by tessera_seal_encrypt(). */
        pub.suite = suite;
        memcpy(pub.pk, pk_buf.buf, TESSERA_SEAL_MLKEM1024_PK_BYTES);
        rc = tessera_seal_encrypt(
            (const uint8_t *) pt_buf.buf, (size_t) pt_buf.len,
            &pub, suite,
            ad_given ? (const uint8_t *) ad_buf.buf : NULL,
            ad_given ? (size_t) ad_buf.len : 0,
            ts_ms, counter,
            (uint8_t *) PyBytes_AS_STRING(out_obj), out_cap, &out_len);
    }
    PyBuffer_Release(&pt_buf);
    PyBuffer_Release(&pk_buf);
    if (ad_given) PyBuffer_Release(&ad_buf);
    if (rc != TESSERA_SEAL_OK) {
        Py_DECREF(out_obj);
        raise_status(rc, "encrypt");
        return NULL;
    }
    if ((size_t) PyBytes_GET_SIZE(out_obj) != out_len) {
        _PyBytes_Resize(&out_obj, (Py_ssize_t) out_len);
    }
    return out_obj;
}

/* decrypt(envelope, sk_bytes, expected_ad=b"") -> plaintext */
static PyObject *py_decrypt(PyObject *self, PyObject *args, PyObject *kwds) {
    (void)self;
    static char *kwlist[] = {"envelope", "sk_bytes", "expected_ad", NULL};
    Py_buffer env_buf;
    Py_buffer sk_buf;
    Py_buffer ad_buf = {0};
    int ad_given = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*y*|y*", kwlist,
                                     &env_buf, &sk_buf, &ad_buf)) return NULL;
    ad_given = ad_buf.buf != NULL;

    /* The binding takes raw sk bytes that carry no suite tag, so adopt the
     * envelope's suite from a structural header peek (TSEAL-00036 / hybrid
     * TSEAL-00034). The same ML-KEM-1024 keypair is valid under any non-hybrid
     * v1 suite (see tessera_seal_generate_keypair()), so this cannot weaken the
     * C library's priv->suite != header.suite BadKey check — it only stops the
     * previous hardcoded 0x01 from rejecting every legitimate suite-0x02
     * envelope. For a hybrid 0x06 header we route to tessera_seal_decrypt_hybrid
     * with the 3200-byte hybrid private key. If the peek fails structurally
     * (truncated, unknown variant/suite), keep the non-hybrid 0x01 default and
     * let tessera_seal_decrypt() surface the structural error on its
     * constant-time path. */
    tessera_seal_header_t hdr = {0};
    uint8_t peeked_suite = TESSERA_SEAL_SUITE_MLKEM1024_AESGCM;
    int peeked = (tessera_seal_peek_header((const uint8_t *) env_buf.buf,
                                           (size_t) env_buf.len, &hdr) == TESSERA_SEAL_OK);
    if (peeked) peeked_suite = hdr.suite;
    int is_hybrid = peeked
        && peeked_suite == TESSERA_SEAL_SUITE_HYBRID_X25519_MLKEM1024_AESGCM;

    size_t want_sk = is_hybrid ? (size_t) TESSERA_SEAL_HYBRID_SK_BYTES
                               : (size_t) TESSERA_SEAL_MLKEM1024_SK_BYTES;
    if ((size_t) sk_buf.len != want_sk) {
        PyBuffer_Release(&env_buf);
        PyBuffer_Release(&sk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        PyErr_Format(TesseraSealError, "sk must be %zu bytes", want_sk);
        return NULL;
    }

    /* Output capacity: envelope size minus the structural overhead. */
    size_t cap = (size_t) env_buf.len;
    PyObject *out_obj = PyBytes_FromStringAndSize(NULL, (Py_ssize_t) cap);
    if (!out_obj) {
        PyBuffer_Release(&env_buf);
        PyBuffer_Release(&sk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        return NULL;
    }
    size_t out_len = cap;
    int rc;
    if (is_hybrid) {
        tessera_seal_priv_hybrid_t priv;
        priv.suite = TESSERA_SEAL_SUITE_HYBRID_X25519_MLKEM1024_AESGCM;
        memcpy(priv.sk, sk_buf.buf, TESSERA_SEAL_HYBRID_SK_BYTES);
        rc = tessera_seal_decrypt_hybrid(
            (const uint8_t *) env_buf.buf, (size_t) env_buf.len,
            &priv,
            ad_given ? (const uint8_t *) ad_buf.buf : NULL,
            ad_given ? (size_t) ad_buf.len : 0,
            (uint8_t *) PyBytes_AS_STRING(out_obj), cap, &out_len);
        tessera_seal_zeroize_priv_hybrid(&priv);
    } else {
        tessera_seal_priv_t priv;
        priv.suite = peeked_suite;
        memcpy(priv.sk, sk_buf.buf, TESSERA_SEAL_MLKEM1024_SK_BYTES);
        rc = tessera_seal_decrypt(
            (const uint8_t *) env_buf.buf, (size_t) env_buf.len,
            &priv,
            ad_given ? (const uint8_t *) ad_buf.buf : NULL,
            ad_given ? (size_t) ad_buf.len : 0,
            (uint8_t *) PyBytes_AS_STRING(out_obj), cap, &out_len);
        tessera_seal_zeroize_priv(&priv);
    }
    PyBuffer_Release(&env_buf);
    PyBuffer_Release(&sk_buf);
    if (ad_given) PyBuffer_Release(&ad_buf);
    if (rc != TESSERA_SEAL_OK) {
        Py_DECREF(out_obj);
        raise_status(rc, "decrypt");
        return NULL;
    }
    _PyBytes_Resize(&out_obj, (Py_ssize_t) out_len);
    return out_obj;
}

/* peek_header(envelope) -> dict */
static PyObject *py_peek_header(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer env_buf;
    if (PyObject_GetBuffer(arg, &env_buf, PyBUF_SIMPLE) != 0) return NULL;
    tessera_seal_header_t h = {0};
    int rc = tessera_seal_peek_header((const uint8_t *) env_buf.buf, (size_t) env_buf.len, &h);
    PyBuffer_Release(&env_buf);
    if (rc != TESSERA_SEAL_OK) { raise_status(rc, "peek_header"); return NULL; }
    return Py_BuildValue("{s:K,s:i,s:i,s:i,s:i,s:I}",
        "timestamp_ms", (unsigned long long) h.timestamp_ms,
        "variant", (int) h.variant,
        "suite", (int) h.suite,
        "counter", (int) h.counter,
        "kem_ct_len", (int) h.kem_ct_len,
        "ad_len", (unsigned int) h.ad_len);
}

/* peek_ad(envelope) -> bytes
 *
 * Structural AD peek (TSEAL-00047): returns a copy of the cleartext-on-wire
 * associated-data bytes WITHOUT decrypting — the routing-before-decrypt
 * companion to peek_header(). Canonical use: TesseraID-as-AD routing.
 *
 * WARNING: the returned bytes are UNAUTHENTICATED until decrypt() succeeds —
 * every byte is attacker-controlled. Routing/lookup only.
 *
 * Rejects exactly what tessera_seal_peek_ad() rejects: everything
 * peek_header rejects (unknown variant/suite, bad declared lengths) plus
 * InvalidLength when the declared AD region extends past the envelope
 * (truncated input). */
static PyObject *py_peek_ad(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer env_buf;
    if (PyObject_GetBuffer(arg, &env_buf, PyBUF_SIMPLE) != 0) return NULL;
    const uint8_t *ad = NULL;
    uint32_t ad_len = 0;
    int rc = tessera_seal_peek_ad((const uint8_t *) env_buf.buf, (size_t) env_buf.len,
                             &ad, &ad_len);
    if (rc != TESSERA_SEAL_OK) {
        PyBuffer_Release(&env_buf);
        raise_status(rc, "peek_ad");
        return NULL;
    }
    /* PyBytes copies, so the zero-copy C pointer never outlives env_buf. */
    PyObject *out = PyBytes_FromStringAndSize((const char *) ad, (Py_ssize_t) ad_len);
    PyBuffer_Release(&env_buf);
    return out;
}

/* validate(envelope) -> bool */
static PyObject *py_validate(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer env_buf;
    if (PyObject_GetBuffer(arg, &env_buf, PyBUF_SIMPLE) != 0) return NULL;
    int ok = tessera_seal_validate((const uint8_t *) env_buf.buf, (size_t) env_buf.len);
    PyBuffer_Release(&env_buf);
    if (ok) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

/* validate_min_timestamp(envelope, min_ms) -> bool */
static PyObject *py_validate_min_timestamp(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer env_buf;
    unsigned long long min_ms;
    if (!PyArg_ParseTuple(args, "y*K", &env_buf, &min_ms)) return NULL;
    int ok = tessera_seal_validate_min_timestamp((const uint8_t *) env_buf.buf, (size_t) env_buf.len, (uint64_t) min_ms);
    PyBuffer_Release(&env_buf);
    if (ok) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

/* set_now_ms_for_testing(value) — pass UINT64_MAX (or negative) to clear */
static PyObject *py_set_now_ms(PyObject *self, PyObject *arg) {
    (void)self;
    if (arg == Py_None) {
        tessera_seal_set_now_ms_for_testing(UINT64_MAX);
    } else {
        unsigned long long v = PyLong_AsUnsignedLongLong(arg);
        if (PyErr_Occurred()) return NULL;
        tessera_seal_set_now_ms_for_testing((uint64_t) v);
    }
    Py_RETURN_NONE;
}

static PyMethodDef Methods[] = {
    {"generate_keypair", (PyCFunction) py_generate_keypair, METH_VARARGS | METH_KEYWORDS,
     "generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes)"},
    {"generate_keypair_hybrid", py_generate_keypair_hybrid, METH_NOARGS,
     "generate_keypair_hybrid() -> (sk_bytes[3200], pk_bytes[1600])  (suite 0x06)"},
    {"generate_keypair_hybrid_from_seed", py_generate_keypair_hybrid_from_seed, METH_O,
     "generate_keypair_hybrid_from_seed(seed[96]) -> (sk_bytes[3200], pk_bytes[1600])"},
    {"encrypt", (PyCFunction) py_encrypt, METH_VARARGS | METH_KEYWORDS,
     "encrypt(pt, pk_bytes, suite=0x01, ad=b\"\", ts_ms=None, counter=0) -> envelope"},
    {"decrypt", (PyCFunction) py_decrypt, METH_VARARGS | METH_KEYWORDS,
     "decrypt(envelope, sk_bytes, expected_ad=b\"\") -> plaintext"},
    {"peek_header", py_peek_header, METH_O,
     "peek_header(envelope) -> dict (structural; does NOT authenticate)"},
    {"peek_ad", py_peek_ad, METH_O,
     "peek_ad(envelope) -> bytes (structural; UNAUTHENTICATED until decrypt() "
     "succeeds — attacker-controlled; routing/lookup only)"},
    {"validate", py_validate, METH_O,
     "validate(envelope) -> bool (structural; does NOT authenticate)"},
    {"validate_min_timestamp", py_validate_min_timestamp, METH_VARARGS,
     "validate_min_timestamp(envelope, min_ms) -> bool"},
    {"set_now_ms_for_testing", py_set_now_ms, METH_O,
     "set_now_ms_for_testing(value | None)"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef tessera_seal_ext_module = {
    PyModuleDef_HEAD_INIT,
    "tessera_seal_ext",
    "CPython extension for TesseraSeal v1 — wraps the C reference.",
    -1,
    Methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_tessera_seal_ext(void) {
    PyObject *m = PyModule_Create(&tessera_seal_ext_module);
    if (!m) return NULL;

    TesseraSealError = PyErr_NewException("tessera_seal_ext.TesseraSealError", NULL, NULL);
    UnknownVariantError = PyErr_NewException("tessera_seal_ext.UnknownVariant", TesseraSealError, NULL);
    UnknownSuiteError = PyErr_NewException("tessera_seal_ext.UnknownSuite", TesseraSealError, NULL);
    InvalidLengthError = PyErr_NewException("tessera_seal_ext.InvalidLength", TesseraSealError, NULL);
    DecryptionError = PyErr_NewException("tessera_seal_ext.DecryptionError", TesseraSealError, NULL);
    BadKeyError = PyErr_NewException("tessera_seal_ext.BadKey", TesseraSealError, NULL);
    Py_INCREF(TesseraSealError);
    Py_INCREF(UnknownVariantError);
    Py_INCREF(UnknownSuiteError);
    Py_INCREF(InvalidLengthError);
    Py_INCREF(DecryptionError);
    Py_INCREF(BadKeyError);
    PyModule_AddObject(m, "TesseraSealError", TesseraSealError);
    PyModule_AddObject(m, "UnknownVariant", UnknownVariantError);
    PyModule_AddObject(m, "UnknownSuite", UnknownSuiteError);
    PyModule_AddObject(m, "InvalidLength", InvalidLengthError);
    PyModule_AddObject(m, "DecryptionError", DecryptionError);
    PyModule_AddObject(m, "BadKey", BadKeyError);

    PyModule_AddIntConstant(m, "VARIANT_TESSERA_SEAL", TESSERA_SEAL_VARIANT);
    PyModule_AddIntConstant(m, "SUITE_MLKEM1024_AESGCM", TESSERA_SEAL_SUITE_MLKEM1024_AESGCM);
    PyModule_AddIntConstant(m, "SUITE_MLKEM1024_CHACHA", TESSERA_SEAL_SUITE_MLKEM1024_CHACHA);
    PyModule_AddIntConstant(m, "SUITE_HYBRID_X25519_MLKEM1024_AESGCM",
                            TESSERA_SEAL_SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    PyModule_AddIntConstant(m, "HEADER_BYTES", TESSERA_SEAL_HEADER_BYTES);
    PyModule_AddIntConstant(m, "MLKEM1024_PK_BYTES", TESSERA_SEAL_MLKEM1024_PK_BYTES);
    PyModule_AddIntConstant(m, "MLKEM1024_SK_BYTES", TESSERA_SEAL_MLKEM1024_SK_BYTES);
    PyModule_AddIntConstant(m, "MLKEM1024_CT_BYTES", TESSERA_SEAL_MLKEM1024_CT_BYTES);
    PyModule_AddIntConstant(m, "HYBRID_PK_BYTES", TESSERA_SEAL_HYBRID_PK_BYTES);
    PyModule_AddIntConstant(m, "HYBRID_SK_BYTES", TESSERA_SEAL_HYBRID_SK_BYTES);
    PyModule_AddIntConstant(m, "HYBRID_CT_BYTES", TESSERA_SEAL_HYBRID_CT_BYTES);
    PyModule_AddIntConstant(m, "HYBRID_SEED_BYTES", TESSERA_SEAL_HYBRID_SEED_BYTES);
    PyModule_AddIntConstant(m, "AEAD_NONCE_BYTES", TESSERA_SEAL_AEAD_NONCE_BYTES);
    PyModule_AddIntConstant(m, "AEAD_TAG_BYTES", TESSERA_SEAL_AEAD_TAG_BYTES);
    PyModule_AddIntConstant(m, "COMMIT_BYTES", TESSERA_SEAL_COMMIT_BYTES);
    return m;
}
