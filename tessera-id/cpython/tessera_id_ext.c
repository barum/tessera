/*
 * tessera_id_ext.c — CPython C extension module for TesseraID.
 *
 * Wraps the C reference implementation (../c/tessera_id.c) and exposes a clean
 * Python-level API. Built with the limited stable ABI (Py_LIMITED_API) so
 * the same .so works across CPython 3.7+ minor versions.
 *
 * Functions:
 *   tessera_id.new()                 -> bytes (41-byte Standard TesseraID, default thread-local generator)
 *   tessera_id.new_hlc(observe=None) -> bytes (41-byte HLC TesseraID; observe is 9-byte peer prefix or None)
 *   tessera_id.encode_b64(b)         -> str  (55-char Base64URL)
 *   tessera_id.encode_b32(b)         -> str  (66-char Crockford Base32)
 *   tessera_id.decode_b64(s)         -> bytes
 *   tessera_id.decode_b32(s)         -> bytes
 *   tessera_id.timestamp_ms(b)       -> int
 *   tessera_id.variant(b)            -> int
 *   tessera_id.counter(b)            -> int
 *
 * Module attributes:
 *   tessera_id.SIZE_BYTES            41
 *   tessera_id.VARIANT_STANDARD      0x01
 *   tessera_id.VARIANT_HLC           0x02
 *   tessera_id.ENCODED_LEN_B64       55
 *   tessera_id.ENCODED_LEN_B32       66
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "tessera_id.h"
#include "tessera_hash.h"

/* Module-level singleton generators (for the convenience API).
 * For multi-threaded use, allocate explicit generators in user code via
 * the future StandardGenerator / HLCGenerator types (not in this minimal
 * extension; one-line workaround: instantiate the module per thread).
 */
static tessera_id_std_generator_t g_std;
static tessera_id_hlc_generator_t g_hlc;

static PyObject *TesseraIdError;

/* Helpers ---------------------------------------------------------------- */
static int raise_status(tessera_id_status_t s, const char *prefix) {
    const char *msg;
    switch (s) {
        case TESSERA_ID_E_RNG:             msg = "CSPRNG failed"; break;
        case TESSERA_ID_E_INVALID_LEN:     msg = "invalid length"; break;
        case TESSERA_ID_E_INVALID_CHAR:    msg = "invalid character"; break;
        case TESSERA_ID_E_PADDING_BITS:    msg = "non-zero padding bits"; break;
        case TESSERA_ID_E_UNKNOWN_VARIANT: msg = "unknown variant byte"; break;
        case TESSERA_ID_E_HLC_DRIFT:       msg = "HLC drift exceeded"; break;
        default:                           msg = "unknown error"; break;
    }
    PyErr_Format(TesseraIdError, "%s: %s", prefix, msg);
    return -1;
}

/* new() -> bytes --------------------------------------------------------- */
static PyObject *py_new(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    uint8_t out[TESSERA_ID_SIZE_BYTES];
    tessera_id_status_t s = tessera_id_std_new(&g_std, out);
    if (s != TESSERA_ID_OK) { raise_status(s, "tessera_id.new"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_ID_SIZE_BYTES);
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
            PyErr_SetString(TesseraIdError, "observe must be a 9-byte buffer");
            return NULL;
        }
        peer9 = (const uint8_t *)buf.buf;
    }

    uint8_t out[TESSERA_ID_SIZE_BYTES];
    tessera_id_status_t s = tessera_id_hlc_new(&g_hlc, peer9, out);
    if (got_buf) PyBuffer_Release(&buf);
    if (s != TESSERA_ID_OK) { raise_status(s, "tessera_id.new_hlc"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_ID_SIZE_BYTES);
}

/* encode_b64(b) -> str --------------------------------------------------- */
static PyObject *py_encode_b64(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) != 0) return NULL;
    if (buf.len != TESSERA_ID_SIZE_BYTES) {
        PyBuffer_Release(&buf);
        PyErr_SetString(TesseraIdError, "TesseraID bytes must be 41 bytes");
        return NULL;
    }
    char out[TESSERA_ID_ENCODED_LEN_B64];
    tessera_id_encode_b64url((const uint8_t *)buf.buf, out);
    PyBuffer_Release(&buf);
    return PyUnicode_FromStringAndSize(out, TESSERA_ID_ENCODED_LEN_B64);
}

/* decode_b64(s) -> bytes ------------------------------------------------- */
static PyObject *py_decode_b64(PyObject *self, PyObject *arg) {
    (void)self;
    Py_ssize_t n;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &n);
    if (s == NULL) return NULL;
    if (n != TESSERA_ID_ENCODED_LEN_B64) {
        PyErr_Format(TesseraIdError, "Base64URL TesseraID must be %d chars, got %zd",
                     TESSERA_ID_ENCODED_LEN_B64, n);
        return NULL;
    }
    uint8_t out[TESSERA_ID_SIZE_BYTES];
    tessera_id_status_t st = tessera_id_decode_b64url(s, out);
    if (st != TESSERA_ID_OK) { raise_status(st, "tessera_id.decode_b64"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_ID_SIZE_BYTES);
}

/* encode_b32(b) -> str --------------------------------------------------- */
static PyObject *py_encode_b32(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) != 0) return NULL;
    if (buf.len != TESSERA_ID_SIZE_BYTES) {
        PyBuffer_Release(&buf);
        PyErr_SetString(TesseraIdError, "TesseraID bytes must be 41 bytes");
        return NULL;
    }
    char out[TESSERA_ID_ENCODED_LEN_B32];
    tessera_id_encode_crockford((const uint8_t *)buf.buf, out);
    PyBuffer_Release(&buf);
    return PyUnicode_FromStringAndSize(out, TESSERA_ID_ENCODED_LEN_B32);
}

/* decode_b32(s) -> bytes ------------------------------------------------- */
static PyObject *py_decode_b32(PyObject *self, PyObject *arg) {
    (void)self;
    Py_ssize_t n;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &n);
    if (s == NULL) return NULL;
    if (n != TESSERA_ID_ENCODED_LEN_B32) {
        PyErr_Format(TesseraIdError, "Crockford TesseraID must be %d chars, got %zd",
                     TESSERA_ID_ENCODED_LEN_B32, n);
        return NULL;
    }
    uint8_t out[TESSERA_ID_SIZE_BYTES];
    tessera_id_status_t st = tessera_id_decode_crockford(s, out);
    if (st != TESSERA_ID_OK) { raise_status(st, "tessera_id.decode_b32"); return NULL; }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_ID_SIZE_BYTES);
}

/* Field accessors -------------------------------------------------------- */
static int get_tessera_id_bytes(PyObject *arg, Py_buffer *buf) {
    if (PyObject_GetBuffer(arg, buf, PyBUF_SIMPLE) != 0) return -1;
    if (buf->len != TESSERA_ID_SIZE_BYTES) {
        PyBuffer_Release(buf);
        PyErr_SetString(TesseraIdError, "TesseraID bytes must be 41 bytes");
        return -1;
    }
    return 0;
}
static PyObject *py_timestamp_ms(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_tessera_id_bytes(arg, &buf) < 0) return NULL;
    uint64_t ts = tessera_id_timestamp_ms((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    return PyLong_FromUnsignedLongLong((unsigned long long)ts);
}
static PyObject *py_variant(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_tessera_id_bytes(arg, &buf) < 0) return NULL;
    uint8_t v = tessera_id_variant((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    return PyLong_FromLong(v);
}
static PyObject *py_counter(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_tessera_id_bytes(arg, &buf) < 0) return NULL;
    uint16_t c = tessera_id_counter((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    return PyLong_FromLong(c);
}

static PyObject *py_validate_min_timestamp(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (get_tessera_id_bytes(arg, &buf) < 0) return NULL;
    int ok = tessera_id_validate_min_timestamp((const uint8_t *)buf.buf);
    PyBuffer_Release(&buf);
    if (ok) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

/* ---------- TesseraHash bindings ---------- */

static tessera_hash_generator_t g_tessera_hash;

/* tessera_hash_hash_only(content) -> bytes (64-byte tail) */
static PyObject *py_tessera_hash_hash_only(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) < 0) return NULL;
    uint8_t tail[TESSERA_HASH_TAIL_BYTES];
    tessera_hash_hash_only((const uint8_t *)buf.buf, (size_t)buf.len, tail);
    PyBuffer_Release(&buf);
    return PyBytes_FromStringAndSize((const char *)tail, TESSERA_HASH_TAIL_BYTES);
}

/* tessera_hash_hash_at(content, timestamp_ms, counter) -> bytes (73 bytes) */
static PyObject *py_tessera_hash_hash_at(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer buf;
    unsigned long long ts;
    unsigned int counter;
    if (!PyArg_ParseTuple(args, "y*KI", &buf, &ts, &counter)) return NULL;
    if (counter > 0xFFFF) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "counter out of range");
        return NULL;
    }
    uint8_t out[TESSERA_HASH_SIZE_BYTES];
    tessera_hash_hash_at((const uint8_t *)buf.buf, (size_t)buf.len,
                         (uint64_t)ts, (uint16_t)counter, out);
    PyBuffer_Release(&buf);
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_HASH_SIZE_BYTES);
}

/* tessera_hash_new(content) -> bytes (73 bytes, uses module-level generator) */
static PyObject *py_tessera_hash_new(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) < 0) return NULL;
    uint8_t out[TESSERA_HASH_SIZE_BYTES];
    tessera_hash_status_t st = tessera_hash_new(&g_tessera_hash, (const uint8_t *)buf.buf,
                                                (size_t)buf.len, out);
    PyBuffer_Release(&buf);
    if (st != TESSERA_HASH_OK) {
        PyErr_SetString(TesseraIdError, "tessera_hash_new failed");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_HASH_SIZE_BYTES);
}

/* tessera_hash_encode_b64(b) -> str (98 chars) */
static PyObject *py_tessera_hash_encode_b64(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) < 0) return NULL;
    if (buf.len != TESSERA_HASH_SIZE_BYTES) {
        PyBuffer_Release(&buf);
        PyErr_SetString(TesseraIdError, "TesseraHash must be 73 bytes");
        return NULL;
    }
    char out[TESSERA_HASH_ENCODED_LEN_B64];
    tessera_hash_encode_b64url((const uint8_t *)buf.buf, out);
    PyBuffer_Release(&buf);
    return PyUnicode_DecodeASCII(out, TESSERA_HASH_ENCODED_LEN_B64, NULL);
}

/* tessera_hash_decode_b64(s) -> bytes (73 bytes) */
static PyObject *py_tessera_hash_decode_b64(PyObject *self, PyObject *arg) {
    (void)self;
    if (!PyUnicode_Check(arg)) { PyErr_SetString(PyExc_TypeError, "expected str"); return NULL; }
    Py_ssize_t len;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &len);
    if (!s) return NULL;
    if (len != TESSERA_HASH_ENCODED_LEN_B64) {
        PyErr_SetString(TesseraIdError, "Base64URL TesseraHash must be 98 chars");
        return NULL;
    }
    uint8_t out[TESSERA_HASH_SIZE_BYTES];
    tessera_hash_status_t st = tessera_hash_decode_b64url(s, out);
    if (st != TESSERA_HASH_OK) {
        PyErr_SetString(TesseraIdError, "TesseraHash decode_b64 failed");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_HASH_SIZE_BYTES);
}

/* tessera_hash_encode_b32(b) -> str (117 chars) */
static PyObject *py_tessera_hash_encode_b32(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) < 0) return NULL;
    if (buf.len != TESSERA_HASH_SIZE_BYTES) {
        PyBuffer_Release(&buf);
        PyErr_SetString(TesseraIdError, "TesseraHash must be 73 bytes");
        return NULL;
    }
    char out[TESSERA_HASH_ENCODED_LEN_B32];
    tessera_hash_encode_crockford((const uint8_t *)buf.buf, out);
    PyBuffer_Release(&buf);
    return PyUnicode_DecodeASCII(out, TESSERA_HASH_ENCODED_LEN_B32, NULL);
}

/* tessera_hash_decode_b32(s) -> bytes (73 bytes) */
static PyObject *py_tessera_hash_decode_b32(PyObject *self, PyObject *arg) {
    (void)self;
    if (!PyUnicode_Check(arg)) { PyErr_SetString(PyExc_TypeError, "expected str"); return NULL; }
    Py_ssize_t len;
    const char *s = PyUnicode_AsUTF8AndSize(arg, &len);
    if (!s) return NULL;
    if (len != TESSERA_HASH_ENCODED_LEN_B32) {
        PyErr_SetString(TesseraIdError, "Crockford TesseraHash must be 117 chars");
        return NULL;
    }
    uint8_t out[TESSERA_HASH_SIZE_BYTES];
    tessera_hash_status_t st = tessera_hash_decode_crockford(s, out);
    if (st != TESSERA_HASH_OK) {
        PyErr_SetString(TesseraIdError, "TesseraHash decode_b32 failed");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)out, TESSERA_HASH_SIZE_BYTES);
}

/* tessera_hash_verify(raw, content) -> bool */
static PyObject *py_tessera_hash_verify(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer raw_buf, content_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &raw_buf, &content_buf)) return NULL;
    int ok = 0;
    if (raw_buf.len == TESSERA_HASH_SIZE_BYTES) {
        ok = tessera_hash_verify((const uint8_t *)raw_buf.buf,
                                 (const uint8_t *)content_buf.buf,
                                 (size_t)content_buf.len);
    }
    PyBuffer_Release(&raw_buf);
    PyBuffer_Release(&content_buf);
    if (ok) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

/* tessera_hash_validate(b) -> None or raises */
static PyObject *py_tessera_hash_validate(PyObject *self, PyObject *arg) {
    (void)self;
    Py_buffer buf;
    if (PyObject_GetBuffer(arg, &buf, PyBUF_SIMPLE) < 0) return NULL;
    tessera_hash_status_t st = (buf.len == TESSERA_HASH_SIZE_BYTES)
        ? tessera_hash_validate((const uint8_t *)buf.buf)
        : TESSERA_HASH_E_INVALID_LEN;
    PyBuffer_Release(&buf);
    if (st != TESSERA_HASH_OK) {
        PyErr_SetString(TesseraIdError, "TesseraHash validate failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

/* Method table ----------------------------------------------------------- */
static PyMethodDef Methods[] = {
    {"new",          py_new,                              METH_NOARGS,  "Generate a Standard TesseraID (41 bytes)."},
    {"new_hlc",      (PyCFunction)py_new_hlc,             METH_VARARGS | METH_KEYWORDS,
        "Generate an HLC TesseraID. Optional 'observe=' is a 9-byte peer clock prefix."},
    {"encode_b64",   py_encode_b64,                       METH_O,       "Encode 41 bytes -> 55-char Base64URL."},
    {"decode_b64",   py_decode_b64,                       METH_O,       "Decode 55-char Base64URL -> 41 bytes."},
    {"encode_b32",   py_encode_b32,                       METH_O,       "Encode 41 bytes -> 66-char Crockford Base32."},
    {"decode_b32",   py_decode_b32,                       METH_O,       "Decode 66-char Crockford Base32 -> 41 bytes."},
    {"timestamp_ms", py_timestamp_ms,                     METH_O,       "Extract 48-bit timestamp (ms) from a TesseraID."},
    {"variant",      py_variant,                          METH_O,       "Extract variant byte (0x01 or 0x02)."},
    {"counter",      py_counter,                          METH_O,       "Extract 16-bit counter."},
    {"validate_min_timestamp", py_validate_min_timestamp, METH_O,       "Non-normative defensive helper: returns True iff timestamp_ms >= MIN_TIMESTAMP_MS."},
    /* TesseraHash */
    {"tessera_hash_hash_only",    py_tessera_hash_hash_only,    METH_O,       "SHAKE-256(content) truncated to 64 bytes."},
    {"tessera_hash_hash_at",      py_tessera_hash_hash_at,      METH_VARARGS, "tessera_hash_hash_at(content, timestamp_ms, counter) -> 73 bytes."},
    {"tessera_hash_new",          py_tessera_hash_new,          METH_O,       "Generate a TesseraHash using the module-level generator (73 bytes)."},
    {"tessera_hash_encode_b64",   py_tessera_hash_encode_b64,   METH_O,       "Encode 73 bytes -> 98-char Base64URL."},
    {"tessera_hash_decode_b64",   py_tessera_hash_decode_b64,   METH_O,       "Decode 98-char Base64URL -> 73 bytes."},
    {"tessera_hash_encode_b32",   py_tessera_hash_encode_b32,   METH_O,       "Encode 73 bytes -> 117-char Crockford Base32."},
    {"tessera_hash_decode_b32",   py_tessera_hash_decode_b32,   METH_O,       "Decode 117-char Crockford Base32 -> 73 bytes."},
    {"tessera_hash_verify",       py_tessera_hash_verify,       METH_VARARGS, "tessera_hash_verify(raw, content) -> bool (constant-time tail compare)."},
    {"tessera_hash_validate",     py_tessera_hash_validate,     METH_O,       "Validate a 73-byte TesseraHash buffer's length and variant."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "tessera_id_ext", NULL, -1, Methods
};

PyMODINIT_FUNC PyInit_tessera_id_ext(void) {
    tessera_id_std_init(&g_std);
    tessera_id_hlc_init(&g_hlc);
    tessera_hash_init(&g_tessera_hash);
    PyObject *m = PyModule_Create(&moduledef);
    if (!m) return NULL;
    TesseraIdError = PyErr_NewException("tessera_id_ext.TesseraIdError", NULL, NULL);
    Py_INCREF(TesseraIdError);
    if (PyModule_AddObject(m, "TesseraIdError", TesseraIdError) < 0) {
        Py_DECREF(TesseraIdError); Py_DECREF(m); return NULL;
    }
    PyModule_AddIntConstant(m, "SIZE_BYTES",       TESSERA_ID_SIZE_BYTES);
    PyModule_AddIntConstant(m, "VARIANT_STANDARD", TESSERA_ID_VARIANT_STANDARD);
    PyModule_AddIntConstant(m, "VARIANT_HLC",      TESSERA_ID_VARIANT_HLC);
    PyModule_AddIntConstant(m, "ENCODED_LEN_B64",  TESSERA_ID_ENCODED_LEN_B64);
    PyModule_AddIntConstant(m, "ENCODED_LEN_B32",  TESSERA_ID_ENCODED_LEN_B32);
    PyModule_AddIntConstant(m, "TESSERA_HASH_SIZE_BYTES",     TESSERA_HASH_SIZE_BYTES);
    PyModule_AddIntConstant(m, "TESSERA_HASH_VARIANT",        TESSERA_HASH_VARIANT);
    PyModule_AddIntConstant(m, "TESSERA_HASH_ENCODED_LEN_B64",TESSERA_HASH_ENCODED_LEN_B64);
    PyModule_AddIntConstant(m, "TESSERA_HASH_ENCODED_LEN_B32",TESSERA_HASH_ENCODED_LEN_B32);
    {
        PyObject *min_ts = PyLong_FromUnsignedLongLong((unsigned long long)TESSERA_ID_MIN_TIMESTAMP_MS);
        if (min_ts) {
            PyModule_AddObject(m, "MIN_TIMESTAMP_MS", min_ts);
        }
    }
    return m;
}
