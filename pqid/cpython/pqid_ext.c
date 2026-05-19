/*
 * pqid_ext.c — CPython C extension module for PQID.
 *
 * Wraps the C reference implementation (../c/pqid.c) and exposes a clean
 * Python-level API. Built with the limited stable ABI (Py_LIMITED_API) so
 * the same .so works across CPython 3.7+ minor versions.
 *
 * Functions:
 *   pqid.new()                 -> bytes (41-byte Standard PQID, default thread-local generator)
 *   pqid.new_hlc(observe=None) -> bytes (41-byte HLC PQID; observe is 9-byte peer prefix or None)
 *   pqid.encode_b64(b)         -> str  (55-char Base64URL)
 *   pqid.encode_b32(b)         -> str  (66-char Crockford Base32)
 *   pqid.decode_b64(s)         -> bytes
 *   pqid.decode_b32(s)         -> bytes
 *   pqid.timestamp_ms(b)       -> int
 *   pqid.variant(b)            -> int
 *   pqid.counter(b)            -> int
 *
 * Module attributes:
 *   pqid.SIZE_BYTES            41
 *   pqid.VARIANT_STANDARD      0x01
 *   pqid.VARIANT_HLC           0x02
 *   pqid.ENCODED_LEN_B64       55
 *   pqid.ENCODED_LEN_B32       66
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../c/pqid.h"

/* Module-level singleton generators (for the convenience API).
 * For multi-threaded use, allocate explicit generators in user code via
 * the future StandardGenerator / HLCGenerator types (not in this minimal
 * extension; one-line workaround: instantiate the module per thread).
 */
static pqid_std_generator_t g_std;
static pqid_hlc_generator_t g_hlc;

static PyObject *PqidError;

/* Helpers ---------------------------------------------------------------- */
static int raise_status(pqid_status_t s, const char *prefix) {
    const char *msg;
    switch (s) {
        case PQID_E_RNG:             msg = "CSPRNG failed"; break;
        case PQID_E_INVALID_LEN:     msg = "invalid length"; break;
        case PQID_E_INVALID_CHAR:    msg = "invalid character"; break;
        case PQID_E_PADDING_BITS:    msg = "non-zero padding bits"; break;
        case PQID_E_UNKNOWN_VARIANT: msg = "unknown variant byte"; break;
        case PQID_E_HLC_DRIFT:       msg = "HLC drift exceeded"; break;
        default:                     msg = "unknown error"; break;
    }
    PyErr_Format(PqidError, "%s: %s", prefix, msg);
    return -1;
}

/* new() -> bytes --------------------------------------------------------- */
static PyObject *py_new(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    uint8_t out[PQID_SIZE_BYTES];
    pqid_status_t s = pqid_std_new(&g_std, out);
    if (s != PQID_OK) { raise_status(s, "pqid.new"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, PQID_SIZE_BYTES);
}

/* new_hlc(observe=None) -> bytes ----------------------------------------- */
static PyObject *py_new_hlc(PyObject *self, PyObject *args, PyObject *kwds) {
    (void)self;
    static char *kwlist[] = {"observe", NULL};
    PyObject *obs = Py_None;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &obs)) return NULL;

    const uint8_t *peer9 = NULL;
    Py_buffer buf;
    int got_buf = 0;
    if (obs != Py_None) {
        if (PyObject_GetBuffer(obs, &buf, PyBUF_SIMPLE) != 0) return NULL;
        got_buf = 1;
        if (buf.len != 9) {
            PyBuffer_Release(&buf);
            PyErr_SetString(PqidError, "observe must be a 9-byte buffer");
            return NULL;
        }
        peer9 = (const uint8_t *)buf.buf;
    }

    uint8_t out[PQID_SIZE_BYTES];
    pqid_status_t s = pqid_hlc_new(&g_hlc, peer9, out);
    if (got_buf) PyBuffer_Release(&buf);
    if (s != PQID_OK) { raise_status(s, "pqid.new_hlc"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, PQID_SIZE_BYTES);
}

/* encode_b64(b) -> str --------------------------------------------------- */
static PyObject *py_encode_b64(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) != 0) return NULL;
    if (buf.len != PQID_SIZE_BYTES) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PqidError, "PQID bytes must be 41 bytes");
        return NULL;
    }
    char out[PQID_ENCODED_LEN_B64];
    pqid_encode_b64url((const uint8_t *)buf.buf, out);
    PyBuffer_Release(&buf);
    return PyUnicode_FromStringAndSize(out, PQID_ENCODED_LEN_B64);
}

/* decode_b64(s) -> bytes ------------------------------------------------- */
static PyObject *py_decode_b64(PyObject *self, PyObject *arg) {
    (void)self;
    Py_ssize_t n;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &n);
    if (s == NULL) return NULL;
    if (n != PQID_ENCODED_LEN_B64) {
        PyErr_Format(PqidError, "Base64URL PQID must be %d chars, got %zd",
                     PQID_ENCODED_LEN_B64, n);
        return NULL;
    }
    uint8_t out[PQID_SIZE_BYTES];
    pqid_status_t st = pqid_decode_b64url(s, out);
    if (st != PQID_OK) { raise_status(st, "pqid.decode_b64"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, PQID_SIZE_BYTES);
}

/* encode_b32(b) -> str --------------------------------------------------- */
static PyObject *py_encode_b32(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) != 0) return NULL;
    if (buf.len != PQID_SIZE_BYTES) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PqidError, "PQID bytes must be 41 bytes");
        return NULL;
    }
    char out[PQID_ENCODED_LEN_B32];
    pqid_encode_crockford((const uint8_t *)buf.buf, out);
    PyBuffer_Release(&buf);
    return PyUnicode_FromStringAndSize(out, PQID_ENCODED_LEN_B32);
}

/* decode_b32(s) -> bytes ------------------------------------------------- */
static PyObject *py_decode_b32(PyObject *self, PyObject *arg) {
    (void)self;
    Py_ssize_t n;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &n);
    if (s == NULL) return NULL;
    if (n != PQID_ENCODED_LEN_B32) {
        PyErr_Format(PqidError, "Crockford PQID must be %d chars, got %zd",
                     PQID_ENCODED_LEN_B32, n);
        return NULL;
    }
    uint8_t out[PQID_SIZE_BYTES];
    pqid_status_t st = pqid_decode_crockford(s, out);
    if (st != PQID_OK) { raise_status(st, "pqid.decode_b32"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, PQID_SIZE_BYTES);
}

/* Field accessors -------------------------------------------------------- */
static int get_pqid_bytes(PyObject *arg, Py_buffer *buf) {
    if (PyObject_GetBuffer(arg, buf, PyBUF_SIMPLE) != 0) return -1;
    if (buf->len != PQID_SIZE_BYTES) {
        PyBuffer_Release(buf);
        PyErr_SetString(PqidError, "PQID bytes must be 41 bytes");
        return -1;
    }
    return 0;
}
static PyObject *py_timestamp_ms(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_pqid_bytes(arg, &buf) < 0) return NULL;
    uint64_t ts = pqid_timestamp_ms((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    return PyLong_FromUnsignedLongLong((unsigned long long)ts);
}
static PyObject *py_variant(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_pqid_bytes(arg, &buf) < 0) return NULL;
    uint8_t v = pqid_variant((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    return PyLong_FromLong(v);
}
static PyObject *py_counter(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_pqid_bytes(arg, &buf) < 0) return NULL;
    uint16_t c = pqid_counter((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    return PyLong_FromLong(c);
}

/* Method table ----------------------------------------------------------- */
static PyMethodDef Methods[] = {
    {"new",          py_new,                              METH_NOARGS,  "Generate a Standard PQID (41 bytes)."},
    {"new_hlc",      (PyCFunction)py_new_hlc,             METH_VARARGS | METH_KEYWORDS,
        "Generate an HLC PQID. Optional 'observe=' is a 9-byte peer clock prefix."},
    {"encode_b64",   py_encode_b64,                       METH_O,       "Encode 41 bytes -> 55-char Base64URL."},
    {"decode_b64",   py_decode_b64,                       METH_O,       "Decode 55-char Base64URL -> 41 bytes."},
    {"encode_b32",   py_encode_b32,                       METH_O,       "Encode 41 bytes -> 66-char Crockford Base32."},
    {"decode_b32",   py_decode_b32,                       METH_O,       "Decode 66-char Crockford Base32 -> 41 bytes."},
    {"timestamp_ms", py_timestamp_ms,                     METH_O,       "Extract 48-bit timestamp (ms) from a PQID."},
    {"variant",      py_variant,                          METH_O,       "Extract variant byte (0x01 or 0x02)."},
    {"counter",      py_counter,                          METH_O,       "Extract 16-bit counter."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "pqid_ext", NULL, -1, Methods
};

PyMODINIT_FUNC PyInit_pqid_ext(void) {
    pqid_std_init(&g_std);
    pqid_hlc_init(&g_hlc);
    PyObject *m = PyModule_Create(&moduledef);
    if (!m) return NULL;
    PqidError = PyErr_NewException("pqid_ext.PqidError", NULL, NULL);
    Py_INCREF(PqidError);
    if (PyModule_AddObject(m, "PqidError", PqidError) < 0) {
        Py_DECREF(PqidError); Py_DECREF(m); return NULL;
    }
    PyModule_AddIntConstant(m, "SIZE_BYTES",       PQID_SIZE_BYTES);
    PyModule_AddIntConstant(m, "VARIANT_STANDARD", PQID_VARIANT_STANDARD);
    PyModule_AddIntConstant(m, "VARIANT_HLC",      PQID_VARIANT_HLC);
    PyModule_AddIntConstant(m, "ENCODED_LEN_B64",  PQID_ENCODED_LEN_B64);
    PyModule_AddIntConstant(m, "ENCODED_LEN_B32",  PQID_ENCODED_LEN_B32);
    return m;
}
