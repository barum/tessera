/*
 * pqcrypt_ext.c — CPython extension binding for the PQCrypt C reference.
 *
 * Mirrors the API surface of pqcrypt/python/pqcrypt.py but routes every
 * call into the C reference (../c/pqcrypt.c + ../../common/c/hkdf_sha3.c)
 * for an order-of-magnitude speedup over the pure-Python kyber-py path.
 *
 * Functions exposed:
 *   generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes)
 *   encrypt(pt, pk_bytes, suite=0x01, ad=b"", ts_ms=None, counter=0) -> envelope
 *   decrypt(envelope, sk_bytes, expected_ad=b"") -> plaintext
 *   peek_header(envelope) -> dict
 *   validate(envelope) -> bool
 *   validate_min_timestamp(envelope, min_ms) -> bool
 *   set_now_ms_for_testing(value)   # value=-1 to clear
 *
 * Sizes match pqcrypt.h. Errors raise PQCryptError (sub-classed per
 * status code).
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "pqcrypt.h"

static PyObject *PQCryptError;
static PyObject *UnknownVariantError;
static PyObject *UnknownSuiteError;
static PyObject *InvalidLengthError;
static PyObject *DecryptionError;

static int raise_status(int rc, const char *where) {
    PyObject *exc = PQCryptError;
    const char *msg = "internal error";
    switch (rc) {
        case PQCRYPT_OK:                 return 0;
        case PQCRYPT_E_INVALID_LEN:      exc = InvalidLengthError; msg = "invalid length"; break;
        case PQCRYPT_E_UNKNOWN_VARIANT:  exc = UnknownVariantError; msg = "unknown variant byte"; break;
        case PQCRYPT_E_UNKNOWN_SUITE:    exc = UnknownSuiteError; msg = "unknown suite byte"; break;
        case PQCRYPT_E_DECRYPT_FAILED:   exc = DecryptionError; msg = "envelope failed authentication"; break;
        case PQCRYPT_E_RNG:              msg = "CSPRNG failure"; break;
        case PQCRYPT_E_BUF_TOO_SMALL:    msg = "output buffer too small"; break;
        case PQCRYPT_E_BAD_KEY:          msg = "bad key"; break;
        default:                         msg = "unknown error"; break;
    }
    PyErr_Format(exc, "%s: %s (rc=%d)", where, msg, rc);
    return -1;
}

/* generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes) */
static PyObject *py_generate_keypair(PyObject *self, PyObject *args, PyObject *kwds) {
    (void)self;
    static char *kwlist[] = {"suite", NULL};
    unsigned char suite = PQCRYPT_SUITE_MLKEM1024_AESGCM;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|b", kwlist, &suite)) return NULL;

    pqcrypt_priv_t priv = {0};
    pqcrypt_pub_t  pub = {0};
    int rc = pqcrypt_generate_keypair(suite, &priv, &pub);
    if (rc != PQCRYPT_OK) { raise_status(rc, "generate_keypair"); return NULL; }
    PyObject *sk = PyBytes_FromStringAndSize((const char *)priv.sk, PQCRYPT_MLKEM1024_SK_BYTES);
    PyObject *pk = PyBytes_FromStringAndSize((const char *)pub.pk, PQCRYPT_MLKEM1024_PK_BYTES);
    pqcrypt_zeroize_priv(&priv);
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
    unsigned char suite = PQCRYPT_SUITE_MLKEM1024_AESGCM;
    PyObject *ts_obj = Py_None;
    unsigned short counter = 0;
    int ad_given = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*y*|by*OH", kwlist,
                                     &pt_buf, &pk_buf, &suite, &ad_buf, &ts_obj, &counter)) {
        return NULL;
    }
    ad_given = ad_buf.buf != NULL;

    if (pk_buf.len != PQCRYPT_MLKEM1024_PK_BYTES) {
        PyBuffer_Release(&pt_buf);
        PyBuffer_Release(&pk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        PyErr_SetString(PQCryptError, "pk must be 1568 bytes");
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

    pqcrypt_pub_t pub;
    pub.suite = suite;
    memcpy(pub.pk, pk_buf.buf, PQCRYPT_MLKEM1024_PK_BYTES);

    size_t out_cap = pqcrypt_encrypt_output_size((size_t) pt_buf.len, (size_t) (ad_given ? ad_buf.len : 0));
    PyObject *out_obj = PyBytes_FromStringAndSize(NULL, (Py_ssize_t) out_cap);
    if (!out_obj) {
        PyBuffer_Release(&pt_buf);
        PyBuffer_Release(&pk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        return NULL;
    }
    size_t out_len = out_cap;
    int rc = pqcrypt_encrypt(
        (const uint8_t *) pt_buf.buf, (size_t) pt_buf.len,
        &pub, suite,
        ad_given ? (const uint8_t *) ad_buf.buf : NULL,
        ad_given ? (size_t) ad_buf.len : 0,
        ts_ms, counter,
        (uint8_t *) PyBytes_AS_STRING(out_obj), out_cap, &out_len);
    PyBuffer_Release(&pt_buf);
    PyBuffer_Release(&pk_buf);
    if (ad_given) PyBuffer_Release(&ad_buf);
    if (rc != PQCRYPT_OK) {
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

    if (sk_buf.len != PQCRYPT_MLKEM1024_SK_BYTES) {
        PyBuffer_Release(&env_buf);
        PyBuffer_Release(&sk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        PyErr_SetString(PQCryptError, "sk must be 3168 bytes");
        return NULL;
    }
    pqcrypt_priv_t priv;
    priv.suite = PQCRYPT_SUITE_MLKEM1024_AESGCM;
    memcpy(priv.sk, sk_buf.buf, PQCRYPT_MLKEM1024_SK_BYTES);

    /* Output capacity: envelope size minus the structural overhead. */
    size_t cap = (size_t) env_buf.len;
    PyObject *out_obj = PyBytes_FromStringAndSize(NULL, (Py_ssize_t) cap);
    if (!out_obj) {
        pqcrypt_zeroize_priv(&priv);
        PyBuffer_Release(&env_buf);
        PyBuffer_Release(&sk_buf);
        if (ad_given) PyBuffer_Release(&ad_buf);
        return NULL;
    }
    size_t out_len = cap;
    int rc = pqcrypt_decrypt(
        (const uint8_t *) env_buf.buf, (size_t) env_buf.len,
        &priv,
        ad_given ? (const uint8_t *) ad_buf.buf : NULL,
        ad_given ? (size_t) ad_buf.len : 0,
        (uint8_t *) PyBytes_AS_STRING(out_obj), cap, &out_len);
    pqcrypt_zeroize_priv(&priv);
    PyBuffer_Release(&env_buf);
    PyBuffer_Release(&sk_buf);
    if (ad_given) PyBuffer_Release(&ad_buf);
    if (rc != PQCRYPT_OK) {
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
    pqcrypt_header_t h = {0};
    int rc = pqcrypt_peek_header((const uint8_t *) env_buf.buf, (size_t) env_buf.len, &h);
    PyBuffer_Release(&env_buf);
    if (rc != PQCRYPT_OK) { raise_status(rc, "peek_header"); return NULL; }
    return Py_BuildValue("{s:K,s:i,s:i,s:i,s:i,s:I}",
        "timestamp_ms", (unsigned long long) h.timestamp_ms,
        "variant", (int) h.variant,
        "suite", (int) h.suite,
        "counter", (int) h.counter,
        "kem_ct_len", (int) h.kem_ct_len,
        "ad_len", (unsigned int) h.ad_len);
}

/* validate(envelope) -> bool */
static PyObject *py_validate(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer env_buf;
    if (PyObject_GetBuffer(arg, &env_buf, PyBUF_SIMPLE) != 0) return NULL;
    int ok = pqcrypt_validate((const uint8_t *) env_buf.buf, (size_t) env_buf.len);
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
    int ok = pqcrypt_validate_min_timestamp((const uint8_t *) env_buf.buf, (size_t) env_buf.len, (uint64_t) min_ms);
    PyBuffer_Release(&env_buf);
    if (ok) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

/* set_now_ms_for_testing(value) — pass UINT64_MAX (or negative) to clear */
static PyObject *py_set_now_ms(PyObject *self, PyObject *arg) {
    (void)self;
    if (arg == Py_None) {
        pqcrypt_set_now_ms_for_testing(UINT64_MAX);
    } else {
        unsigned long long v = PyLong_AsUnsignedLongLong(arg);
        if (PyErr_Occurred()) return NULL;
        pqcrypt_set_now_ms_for_testing((uint64_t) v);
    }
    Py_RETURN_NONE;
}

static PyMethodDef Methods[] = {
    {"generate_keypair", (PyCFunction) py_generate_keypair, METH_VARARGS | METH_KEYWORDS,
     "generate_keypair(suite=0x01) -> (sk_bytes, pk_bytes)"},
    {"encrypt", (PyCFunction) py_encrypt, METH_VARARGS | METH_KEYWORDS,
     "encrypt(pt, pk_bytes, suite=0x01, ad=b\"\", ts_ms=None, counter=0) -> envelope"},
    {"decrypt", (PyCFunction) py_decrypt, METH_VARARGS | METH_KEYWORDS,
     "decrypt(envelope, sk_bytes, expected_ad=b\"\") -> plaintext"},
    {"peek_header", py_peek_header, METH_O,
     "peek_header(envelope) -> dict (structural; does NOT authenticate)"},
    {"validate", py_validate, METH_O,
     "validate(envelope) -> bool (structural; does NOT authenticate)"},
    {"validate_min_timestamp", py_validate_min_timestamp, METH_VARARGS,
     "validate_min_timestamp(envelope, min_ms) -> bool"},
    {"set_now_ms_for_testing", py_set_now_ms, METH_O,
     "set_now_ms_for_testing(value | None)"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pqcrypt_ext_module = {
    PyModuleDef_HEAD_INIT,
    "pqcrypt_ext",
    "CPython extension for PQCrypt v1 — wraps the C reference.",
    -1,
    Methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_pqcrypt_ext(void) {
    PyObject *m = PyModule_Create(&pqcrypt_ext_module);
    if (!m) return NULL;

    PQCryptError = PyErr_NewException("pqcrypt_ext.PQCryptError", NULL, NULL);
    UnknownVariantError = PyErr_NewException("pqcrypt_ext.UnknownVariant", PQCryptError, NULL);
    UnknownSuiteError = PyErr_NewException("pqcrypt_ext.UnknownSuite", PQCryptError, NULL);
    InvalidLengthError = PyErr_NewException("pqcrypt_ext.InvalidLength", PQCryptError, NULL);
    DecryptionError = PyErr_NewException("pqcrypt_ext.DecryptionError", PQCryptError, NULL);
    Py_INCREF(PQCryptError);
    Py_INCREF(UnknownVariantError);
    Py_INCREF(UnknownSuiteError);
    Py_INCREF(InvalidLengthError);
    Py_INCREF(DecryptionError);
    PyModule_AddObject(m, "PQCryptError", PQCryptError);
    PyModule_AddObject(m, "UnknownVariant", UnknownVariantError);
    PyModule_AddObject(m, "UnknownSuite", UnknownSuiteError);
    PyModule_AddObject(m, "InvalidLength", InvalidLengthError);
    PyModule_AddObject(m, "DecryptionError", DecryptionError);

    PyModule_AddIntConstant(m, "VARIANT_PQCRYPT", PQCRYPT_VARIANT);
    PyModule_AddIntConstant(m, "SUITE_MLKEM1024_AESGCM", PQCRYPT_SUITE_MLKEM1024_AESGCM);
    PyModule_AddIntConstant(m, "SUITE_MLKEM1024_CHACHA", PQCRYPT_SUITE_MLKEM1024_CHACHA);
    PyModule_AddIntConstant(m, "HEADER_BYTES", PQCRYPT_HEADER_BYTES);
    PyModule_AddIntConstant(m, "MLKEM1024_PK_BYTES", PQCRYPT_MLKEM1024_PK_BYTES);
    PyModule_AddIntConstant(m, "MLKEM1024_SK_BYTES", PQCRYPT_MLKEM1024_SK_BYTES);
    PyModule_AddIntConstant(m, "MLKEM1024_CT_BYTES", PQCRYPT_MLKEM1024_CT_BYTES);
    PyModule_AddIntConstant(m, "AEAD_NONCE_BYTES", PQCRYPT_AEAD_NONCE_BYTES);
    PyModule_AddIntConstant(m, "AEAD_TAG_BYTES", PQCRYPT_AEAD_TAG_BYTES);
    PyModule_AddIntConstant(m, "COMMIT_BYTES", PQCRYPT_COMMIT_BYTES);
    return m;
}
