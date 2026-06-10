package com.tessera.conformance;

import com.tessera.id.TesseraId;
import com.tessera.id.Codec;
import com.tessera.id.HLCGenerator;
import com.tessera.hash.TesseraHash;
import com.tessera.hash.TesseraHashCodec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Java conformance runner. Usage: java com.tessera.conformance.ConformanceRunner <vectors.json>
 *
 * Uses iterative string-search rather than a real JSON parser (the vector
 * schema is fixed and we're zero-dep on purpose). Field extraction is
 * deliberately regex-free: java.util.regex recurses once per character for
 * patterns like ((?:[^"\\]|\\.)*) , which overflows a 1 MB Linux default
 * thread stack on the 2048-char hex fields in the tessera-hash vectors
 * (StackOverflowError, TESS-00007 / TP-011).
 */
public final class ConformanceRunner {

    static final class Rec {
        String name = "";
        String op = "";
        String inputHex = "";
        String inputStr = "";
        String inputKind = "";
        String expectedHex = "";
        String expectedStr = "";
        String body = "";
    }

    static List<String> splitObjects(String s) {
        List<String> out = new ArrayList<>();
        int depth = 0; boolean inStr = false; boolean esc = false;
        int begin = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) { esc = false; continue; }
            if (inStr) {
                if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '{') { if (depth == 0) begin = i; depth++; }
                else if (c == '}') {
                    depth--;
                    if (depth == 0 && begin >= 0) {
                        out.add(s.substring(begin, i + 1));
                        begin = -1;
                    }
                }
            }
        }
        return out;
    }

    /**
     * Iteratively locate the first occurrence of {@code key} used as a JSON
     * key (a string immediately followed by ':') and return the index of the
     * first character of its value, or -1. Tracks in-string state with escape
     * handling, exactly like {@link #splitObjects}. Constant stack depth.
     */
    static int valueStart(String rec, String key) {
        boolean inStr = false;
        boolean esc = false;
        int strBegin = -1;
        int n = rec.length();
        for (int i = 0; i < n; i++) {
            char c = rec.charAt(i);
            if (esc) { esc = false; continue; }
            if (inStr) {
                if (c == '\\') { esc = true; continue; }
                if (c != '"') continue;
                inStr = false;
                int j = i + 1;
                while (j < n && Character.isWhitespace(rec.charAt(j))) j++;
                if (j < n && rec.charAt(j) == ':'
                        && i - strBegin - 1 == key.length()
                        && rec.regionMatches(strBegin + 1, key, 0, key.length())) {
                    j++;
                    while (j < n && Character.isWhitespace(rec.charAt(j))) j++;
                    return j < n ? j : -1;
                }
            } else if (c == '"') {
                inStr = true;
                strBegin = i;
            }
        }
        return -1;
    }

    /** Raw content of the string value for {@code key} (escapes kept verbatim,
     *  matching the old regex group semantics), or null. Iterative. */
    static String getStr(String rec, String key) {
        int v = valueStart(rec, key);
        if (v < 0 || rec.charAt(v) != '"') return null;
        int n = rec.length();
        for (int i = v + 1; i < n; i++) {
            char c = rec.charAt(i);
            if (c == '\\') { i++; continue; }
            if (c == '"') return rec.substring(v + 1, i);
        }
        return null;
    }

    static Long getInt(String rec, String key) {
        int v = valueStart(rec, key);
        if (v < 0) return null;
        int n = rec.length();
        int i = v;
        if (i < n && rec.charAt(i) == '-') i++;
        int digitsBegin = i;
        while (i < n && rec.charAt(i) >= '0' && rec.charAt(i) <= '9') i++;
        if (i == digitsBegin) return null;
        return Long.parseLong(rec.substring(v, i));
    }

    /** Body (between braces, exclusive) of the object value for {@code key},
     *  or null. Handles nested braces and strings iteratively. */
    static String getObj(String rec, String key) {
        int v = valueStart(rec, key);
        if (v < 0 || rec.charAt(v) != '{') return null;
        int depth = 0;
        boolean inStr = false;
        boolean esc = false;
        for (int i = v; i < rec.length(); i++) {
            char c = rec.charAt(i);
            if (esc) { esc = false; continue; }
            if (inStr) {
                if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return rec.substring(v + 1, i);
            }
        }
        return null;
    }

    static Boolean getBool(String rec, String key) {
        int v = valueStart(rec, key);
        if (v < 0) return null;
        if (rec.startsWith("true", v)) return Boolean.TRUE;
        if (rec.startsWith("false", v)) return Boolean.FALSE;
        return null;
    }

    static byte[] hexToBytes(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    static boolean isNullField(String rec, String key) {
        int v = valueStart(rec, key);
        return v >= 0 && rec.startsWith("null", v);
    }

    static class Result {
        final boolean ok;
        final String detail;
        Result(boolean ok, String d) { this.ok = ok; this.detail = d; }
    }

    static Result opDecode(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        try {
            TesseraId p = new TesseraId(raw);
            // "expected" is a JSON object; pull its body, then read fields out of it.
            String e = getObj(rec, "expected");
            if (e == null) return new Result(false, "no expected");
            long wantVariant = getInt(e, "variant");
            long wantTs = getInt(e, "timestamp_ms");
            long wantCtr = getInt(e, "counter");
            String wantRand = getStr(e, "random_hex");
            if ((p.variant() & 0xFF) != wantVariant) return new Result(false, "variant mismatch");
            if (p.timestampMs() != wantTs) return new Result(false, "ts mismatch");
            if ((p.counter() & 0xFFFF) != wantCtr) return new Result(false, "counter mismatch");
            byte[] rnd = new byte[32];
            System.arraycopy(p.bytesNoCopy(), 9, rnd, 0, 32);
            String gotRand = bytesToHex(rnd);
            if (!gotRand.equals(wantRand)) return new Result(false, "random got=" + gotRand + " want=" + wantRand);
            return new Result(true, "");
        } catch (Exception e) {
            return new Result(false, "exception: " + e.getMessage());
        }
    }

    static Result opEncodeB64(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        TesseraId p = new TesseraId(raw);
        String got = Codec.encodeBase64Url(p);
        String want = getStr(rec, "expected_str");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opDecodeB64(String rec) {
        try {
            TesseraId p = Codec.decodeBase64Url(getStr(rec, "input_str"));
            String got = bytesToHex(p.bytesNoCopy());
            String want = getStr(rec, "expected_hex");
            if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
            return new Result(true, "");
        } catch (Exception e) {
            return new Result(false, "exception: " + e.getMessage());
        }
    }

    static Result opEncodeCrockford(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        TesseraId p = new TesseraId(raw);
        String got = Codec.encodeCrockford(p);
        String want = getStr(rec, "expected_str");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opDecodeCrockford(String rec) {
        try {
            TesseraId p = Codec.decodeCrockford(getStr(rec, "input_str"));
            String got = bytesToHex(p.bytesNoCopy());
            String want = getStr(rec, "expected_hex");
            if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
            return new Result(true, "");
        } catch (Exception e) {
            return new Result(false, "exception: " + e.getMessage());
        }
    }

    static Result opValidateInvalid(String rec) {
        String kind = getStr(rec, "input_kind");
        try {
            if ("binary_hex".equals(kind)) {
                String h = getStr(rec, "input_hex");
                if (h.length() != 2 * TesseraId.SIZE_BYTES) return new Result(true, "");
                TesseraId p = new TesseraId(hexToBytes(h));
                byte v = p.variant();
                if (v != TesseraId.VARIANT_STANDARD && v != TesseraId.VARIANT_HLC) {
                    return new Result(true, "");
                }
                return new Result(false, "expected error, got success");
            } else if ("b64".equals(kind)) {
                Codec.decodeBase64Url(getStr(rec, "input_str"));
                return new Result(false, "expected error, got success");
            } else if ("crockford".equals(kind)) {
                Codec.decodeCrockford(getStr(rec, "input_str"));
                return new Result(false, "expected error, got success");
            }
        } catch (Exception e) {
            return new Result(true, "");
        }
        return new Result(false, "unknown kind " + kind);
    }

    static Result opValidateMinTimestamp(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        TesseraId p = new TesseraId(raw);
        boolean got = p.validateMinTimestamp();
        // "expected" is a bare boolean.
        Boolean want = getBool(rec, "expected");
        if (want == null) return new Result(false, "no expected bool");
        if (got != want) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    // ---- TesseraHash ops ----

    static Result opTesseraHashHashOnly(String rec) {
        byte[] content = hexToBytes(getStr(rec, "input_hex"));
        byte[] tail = TesseraHash.hashOnly(content);
        String got = bytesToHex(tail);
        String want = getStr(rec, "expected_tail_hex");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opTesseraHashDecode(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        try {
            TesseraHash p = new TesseraHash(raw);
            String e = getObj(rec, "expected");
            if (e == null) return new Result(false, "no expected");
            long wantVariant = getInt(e, "variant");
            long wantTs = getInt(e, "timestamp_ms");
            long wantCtr = getInt(e, "counter");
            String wantTail = getStr(e, "tail_hex");
            if ((p.variant() & 0xFF) != wantVariant) return new Result(false, "variant");
            if (p.timestampMs() != wantTs) return new Result(false, "ts");
            if (p.counter() != wantCtr) return new Result(false, "counter");
            String gotTail = bytesToHex(p.tail());
            if (!gotTail.equals(wantTail)) return new Result(false, "tail got=" + gotTail + " want=" + wantTail);
            return new Result(true, "");
        } catch (Exception ex) {
            return new Result(false, "exception: " + ex.getMessage());
        }
    }

    static Result opTesseraHashEncodeB64(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        TesseraHash p = new TesseraHash(raw);
        String got = TesseraHashCodec.encodeBase64Url(p);
        String want = getStr(rec, "expected_str");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opTesseraHashDecodeB64(String rec) {
        try {
            TesseraHash p = TesseraHashCodec.decodeBase64Url(getStr(rec, "input_str"));
            String got = bytesToHex(p.bytesNoCopy());
            String want = getStr(rec, "expected_hex");
            if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
            return new Result(true, "");
        } catch (Exception ex) {
            return new Result(false, "exception: " + ex.getMessage());
        }
    }

    static Result opTesseraHashEncodeCrockford(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        TesseraHash p = new TesseraHash(raw);
        String got = TesseraHashCodec.encodeCrockford(p);
        String want = getStr(rec, "expected_str");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opTesseraHashDecodeCrockford(String rec) {
        try {
            TesseraHash p = TesseraHashCodec.decodeCrockford(getStr(rec, "input_str"));
            String got = bytesToHex(p.bytesNoCopy());
            String want = getStr(rec, "expected_hex");
            if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
            return new Result(true, "");
        } catch (Exception ex) {
            return new Result(false, "exception: " + ex.getMessage());
        }
    }

    static Result opTesseraHashValidateInvalid(String rec) {
        String kind = getStr(rec, "input_kind");
        try {
            if ("binary_hex".equals(kind)) {
                String h = getStr(rec, "input_hex");
                if (h.length() != 2 * TesseraHash.SIZE_BYTES) return new Result(true, "");
                new TesseraHash(hexToBytes(h));
                return new Result(false, "expected error, got success");
            } else if ("b64".equals(kind)) {
                TesseraHashCodec.decodeBase64Url(getStr(rec, "input_str"));
                return new Result(false, "expected error, got success");
            } else if ("crockford".equals(kind)) {
                TesseraHashCodec.decodeCrockford(getStr(rec, "input_str"));
                return new Result(false, "expected error, got success");
            }
        } catch (Exception ex) {
            return new Result(true, "");
        }
        return new Result(false, "unknown kind " + kind);
    }

    static Result opTesseraHashVerify(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        byte[] content = hexToBytes(getStr(rec, "content_hex"));
        TesseraHash p = new TesseraHash(raw);
        boolean got = p.verify(content);
        Boolean want = getBool(rec, "expected");
        if (want == null) return new Result(false, "no expected bool");
        if (got != want) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    // Two record shapes share this op (hlc_overflow.json and hlc_drift.json,
    // TESS-00009 / TP-043): records with "expected" assert the resulting
    // (l_new, c_new); records with "expects_error": "HLC_DRIFT" assert that
    // generation throws HLCGenerator.HLCDriftError and produces no output —
    // success there is a FAIL.
    static Result opHlcOverflow(String rec) {
        String startBody = getObj(rec, "start");
        if (startBody == null) return new Result(false, "no start");
        long lOld = getInt(startBody, "l_old");
        long cOld = getInt(startBody, "c_old");
        long pt = getInt(rec, "physical_time_ms");
        String expectsError = getStr(rec, "expects_error");
        long expL = 0;
        long expC = 0;
        if (expectsError == null) {
            String e = getObj(rec, "expected");
            if (e == null) return new Result(false, "no expected");
            expL = getInt(e, "l_new");
            expC = getInt(e, "c_new");
        } else if (!"HLC_DRIFT".equals(expectsError)) {
            return new Result(false, "unsupported expects_error " + expectsError);
        }

        HLCGenerator g = new HLCGenerator();
        g.setStateForTesting(lOld, (int) cOld);
        HLCGenerator.setNowMsForTesting(pt);

        TesseraId out;
        try {
            if (isNullField(rec, "observe")) {
                out = g.next();
            } else {
                String obsBody = getObj(rec, "observe");
                long lMsg = getInt(obsBody, "l_msg");
                long cMsg = getInt(obsBody, "c_msg");
                out = g.nextObserving(lMsg, (int) cMsg);
            }
        } catch (HLCGenerator.HLCDriftError ex) {
            if (expectsError != null) return new Result(true, "");
            return new Result(false, "threw HLCDriftError unexpectedly");
        } catch (Exception ex) {
            return new Result(false, "exception: " + ex.getMessage());
        } finally {
            HLCGenerator.setNowMsForTesting(Long.MIN_VALUE);
        }

        if (expectsError != null) {
            return new Result(false, "expected HLC_DRIFT error, got success");
        }
        if (out.timestampMs() != expL || (out.counter() & 0xFFFF) != expC) {
            return new Result(false, String.format("got=(l=%d, c=%d) want=(l=%d, c=%d)",
                out.timestampMs(), out.counter() & 0xFFFF, expL, expC));
        }
        return new Result(true, "");
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: ConformanceRunner <vectors.json>");
            System.exit(2);
        }
        String data = Files.readString(Paths.get(args[0]));
        List<String> records = splitObjects(data);
        int failures = 0;
        for (String rec : records) {
            String name = getStr(rec, "name");
            String op = getStr(rec, "op");
            // 'doc' pseudo-records are documentation, not executable tests.
            // Emit an explicit SKIP line so the harness can reconcile record
            // counts (TESS-00007 / TP-021).
            if ("doc".equals(name)) { System.out.println("SKIP " + name + " (doc pseudo-record)"); continue; }
            Result r;
            try {
                switch (op) {
                    case "decode": r = opDecode(rec); break;
                    case "encode_b64": r = opEncodeB64(rec); break;
                    case "decode_b64": r = opDecodeB64(rec); break;
                    case "encode_crockford": r = opEncodeCrockford(rec); break;
                    case "decode_crockford": r = opDecodeCrockford(rec); break;
                    case "validate_invalid": r = opValidateInvalid(rec); break;
                    case "hlc_overflow": r = opHlcOverflow(rec); break;
                    case "validate_min_timestamp": r = opValidateMinTimestamp(rec); break;
                    case "tessera_hash_hash_only":       r = opTesseraHashHashOnly(rec); break;
                    case "tessera_hash_decode":          r = opTesseraHashDecode(rec); break;
                    case "tessera_hash_encode_b64":      r = opTesseraHashEncodeB64(rec); break;
                    case "tessera_hash_decode_b64":      r = opTesseraHashDecodeB64(rec); break;
                    case "tessera_hash_encode_crockford": r = opTesseraHashEncodeCrockford(rec); break;
                    case "tessera_hash_decode_crockford": r = opTesseraHashDecodeCrockford(rec); break;
                    case "tessera_hash_validate_invalid": r = opTesseraHashValidateInvalid(rec); break;
                    case "tessera_hash_verify":          r = opTesseraHashVerify(rec); break;
                    default: r = new Result(false, "unknown op " + op);
                }
            } catch (Exception ex) {
                r = new Result(false, "harness exception: " + ex.getMessage());
            }
            if (r.ok) System.out.println("PASS " + name);
            else { System.out.println("FAIL " + name + " " + r.detail); failures++; }
        }
        System.exit(failures > 0 ? 1 : 0);
    }
}
