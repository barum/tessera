package com.pqid;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.List;

/**
 * Java conformance runner. Usage: java com.pqid.ConformanceRunner <vectors.json>
 *
 * Uses regex string-search rather than a real JSON parser (the vector schema
 * is fixed and we're zero-dep on purpose).
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

    static String getStr(String rec, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(rec);
        return m.find() ? m.group(1) : null;
    }

    static Long getInt(String rec, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)");
        Matcher m = p.matcher(rec);
        return m.find() ? Long.parseLong(m.group(1)) : null;
    }

    static String getNested(String rec, String obj, String key) {
        Pattern p = Pattern.compile("\"" + obj + "\"\\s*:\\s*\\{([^{}]*)\\}");
        Matcher m = p.matcher(rec);
        if (!m.find()) return null;
        return m.group(1);
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
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*null");
        return p.matcher(rec).find();
    }

    static class Result {
        final boolean ok;
        final String detail;
        Result(boolean ok, String d) { this.ok = ok; this.detail = d; }
    }

    static Result opDecode(String rec) {
        byte[] raw = hexToBytes(getStr(rec, "input_hex"));
        try {
            Pqid p = new Pqid(raw);
            // "expected" is a JSON object; pull its body, then read fields out of it.
            Pattern exp = Pattern.compile("\"expected\"\\s*:\\s*\\{(.*?)\\}", Pattern.DOTALL);
            Matcher m = exp.matcher(rec);
            if (!m.find()) return new Result(false, "no expected");
            String e = m.group(1);
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
        Pqid p = new Pqid(raw);
        String got = Codec.encodeBase64Url(p);
        String want = getStr(rec, "expected_str");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opDecodeB64(String rec) {
        try {
            Pqid p = Codec.decodeBase64Url(getStr(rec, "input_str"));
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
        Pqid p = new Pqid(raw);
        String got = Codec.encodeCrockford(p);
        String want = getStr(rec, "expected_str");
        if (!got.equals(want)) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opDecodeCrockford(String rec) {
        try {
            Pqid p = Codec.decodeCrockford(getStr(rec, "input_str"));
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
                if (h.length() != 2 * Pqid.SIZE_BYTES) return new Result(true, "");
                Pqid p = new Pqid(hexToBytes(h));
                byte v = p.variant();
                if (v != Pqid.VARIANT_STANDARD && v != Pqid.VARIANT_HLC) {
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
        Pqid p = new Pqid(raw);
        boolean got = p.validateMinTimestamp();
        // "expected" is a bare boolean.
        Pattern p2 = Pattern.compile("\"expected\"\\s*:\\s*(true|false)");
        Matcher m = p2.matcher(rec);
        if (!m.find()) return new Result(false, "no expected bool");
        boolean want = Boolean.parseBoolean(m.group(1));
        if (got != want) return new Result(false, "got=" + got + " want=" + want);
        return new Result(true, "");
    }

    static Result opHlcOverflow(String rec) {
        String startBody = getNested(rec, "start", "");
        if (startBody == null) return new Result(false, "no start");
        long lOld = getInt(startBody, "l_old");
        long cOld = getInt(startBody, "c_old");
        long pt = getInt(rec, "physical_time_ms");
        Pattern exp = Pattern.compile("\"expected\"\\s*:\\s*\\{(.*?)\\}", Pattern.DOTALL);
        Matcher m = exp.matcher(rec);
        if (!m.find()) return new Result(false, "no expected");
        String e = m.group(1);
        long expL = getInt(e, "l_new");
        long expC = getInt(e, "c_new");

        HLCGenerator g = new HLCGenerator();
        g.setStateForTesting(lOld, (int) cOld);
        HLCGenerator.setNowMsForTesting(pt);

        Pqid out;
        try {
            if (isNullField(rec, "observe")) {
                out = g.next();
            } else {
                String obsBody = getNested(rec, "observe", "");
                long lMsg = getInt(obsBody, "l_msg");
                long cMsg = getInt(obsBody, "c_msg");
                out = g.nextObserving(lMsg, (int) cMsg);
            }
        } catch (Exception ex) {
            HLCGenerator.setNowMsForTesting(Long.MIN_VALUE);
            return new Result(false, "exception: " + ex.getMessage());
        } finally {
            HLCGenerator.setNowMsForTesting(Long.MIN_VALUE);
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
            if ("doc".equals(name)) continue;
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
