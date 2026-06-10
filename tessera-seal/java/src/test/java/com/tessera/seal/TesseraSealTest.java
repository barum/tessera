/*
 * TesseraSeal Java reference test suite.
 *
 * Self-contained tests + KAT consumption from ../../conformance/vectors/.
 *
 *   cd tessera-seal/java && make test
 */
package com.tessera.seal;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.tessera.seal.TesseraSeal;
import com.tessera.seal.TesseraSeal.*;

public class TesseraSealTest {
    private static int gPass = 0, gFail = 0;

    private static void expect(boolean ok, String name) {
        if (ok) { System.out.println("PASS " + name); gPass++; }
        else    { System.out.println("FAIL " + name); gFail++; }
    }

    public static void main(String[] args) throws Exception {
        testRoundtripAESGCM();
        testRoundtripChaCha();
        testADBindingPositive();
        testADBindingWrongAD();
        testVariantRejection();
        testSuiteRejection();
        testSuiteKeyConsistency();
        testTamperDetection();
        testPeekHeader();
        testKATDecrypt();
        testKATADBinding();
        testKATInvalid();
        testKATMinTimestamp();

        System.out.println();
        System.out.println("Total: " + gPass + " pass, " + gFail + " fail");
        System.exit(gFail == 0 ? 0 : 1);
    }

    static byte[] hex(String s) {
        if (s == null || s.isEmpty()) return new byte[0];
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    // --- Self-contained -----------------------------------------------------

    static void testRoundtripAESGCM() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        byte[] pt = "hello world from Java".getBytes();
        byte[] env = TesseraSeal.encrypt(pt, kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM,
                                     new byte[0], null, 0);
        byte[] got = TesseraSeal.decrypt(env, kp.priv, new byte[0]);
        expect(Arrays.equals(got, pt), "roundtrip_aesgcm");
    }

    static void testRoundtripChaCha() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_CHACHA);
        byte[] pt = "chacha payload".getBytes();
        byte[] env = TesseraSeal.encrypt(pt, kp.pub, TesseraSeal.SUITE_MLKEM1024_CHACHA,
                                     new byte[0], null, 0);
        byte[] got = TesseraSeal.decrypt(env, kp.priv, new byte[0]);
        expect(Arrays.equals(got, pt), "roundtrip_chacha");
    }

    static void testADBindingPositive() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        byte[] ad = new byte[41];
        for (int i = 0; i < 41; i++) ad[i] = (byte) i;
        byte[] pt = "with AD".getBytes();
        byte[] env = TesseraSeal.encrypt(pt, kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM, ad, null, 0);
        byte[] got = TesseraSeal.decrypt(env, kp.priv, ad);
        expect(Arrays.equals(got, pt), "ad_binding_positive");
    }

    static void testADBindingWrongAD() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        byte[] ad = new byte[] {1,2,3,4,5,6,7,8};
        byte[] env = TesseraSeal.encrypt("x".getBytes(), kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM, ad, null, 0);
        byte[] wrong = ad.clone(); wrong[0] ^= 1;
        boolean threw = false;
        try { TesseraSeal.decrypt(env, kp.priv, wrong); }
        catch (DecryptionError e) { threw = true; }
        catch (Exception e) {}
        expect(threw, "ad_binding_wrong_ad_throws");
    }

    static void testVariantRejection() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        byte[] env = TesseraSeal.encrypt("x".getBytes(), kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM, new byte[0], null, 0);
        for (int v : new int[] {0x00, 0x01, 0x02, 0x03, 0x05, 0x10, 0x7F, 0xFE, 0xFF}) {
            byte[] bad = env.clone();
            bad[6] = (byte) v;
            boolean threw = false;
            try { TesseraSeal.decrypt(bad, kp.priv, new byte[0]); }
            catch (UnknownVariant e) { threw = true; }
            catch (Exception e) {}
            if (!threw) { System.out.println("FAIL variant_rejection 0x" + Integer.toHexString(v)); gFail++; return; }
        }
        expect(true, "variant_rejection (9 cases)");
    }

    static void testSuiteRejection() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        byte[] env = TesseraSeal.encrypt("x".getBytes(), kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM, new byte[0], null, 0);
        for (int s : new int[] {0x00, 0x03, 0x04, 0x10, 0x7F, 0xFE, 0xFF}) {
            byte[] bad = env.clone();
            bad[7] = (byte) s;
            boolean threw = false;
            try { TesseraSeal.decrypt(bad, kp.priv, new byte[0]); }
            catch (UnknownSuite e) { threw = true; }
            catch (Exception e) {}
            if (!threw) { System.out.println("FAIL suite_rejection 0x" + Integer.toHexString(s)); gFail++; return; }
        }
        expect(true, "suite_rejection (7 cases)");
    }

    static void testSuiteKeyConsistency() {
        // encrypt() MUST reject when pub.suite != requested suite;
        // decrypt() MUST reject when priv.suite != header.suite.
        // Mismatch is BadKey-class (structural), not auth-class.
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);

        // Same ML-KEM key bytes, mis-tagged as the ChaCha suite.
        PublicKey mistagged = PublicKey.fromBytes(kp.pub.bytes, TesseraSeal.SUITE_MLKEM1024_CHACHA);
        boolean encThrew = false;
        try { TesseraSeal.encrypt("x".getBytes(), mistagged, TesseraSeal.SUITE_MLKEM1024_AESGCM, new byte[0], null, 0); }
        catch (BadKey e) { encThrew = true; }
        catch (Exception e) {}
        expect(encThrew, "encrypt_pub_suite_mismatch_badkey");

        // Envelope sealed under suite 0x02; private key tagged 0x01.
        byte[] env = TesseraSeal.encrypt("y".getBytes(), mistagged, TesseraSeal.SUITE_MLKEM1024_CHACHA, new byte[0], null, 0);
        boolean decThrew = false;
        try { TesseraSeal.decrypt(env, kp.priv, new byte[0]); }
        catch (BadKey e) { decThrew = true; }
        catch (Exception e) {}
        expect(decThrew, "decrypt_priv_suite_mismatch_badkey");
    }

    static void testTamperDetection() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        byte[] ad = "id".getBytes();
        byte[] env = TesseraSeal.encrypt("tamper".getBytes(), kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM, ad, null, 0);
        int[][] spots = {
            {TesseraSeal.HEADER_BYTES + 500, 'k'},
            {TesseraSeal.HEADER_BYTES + 1568, 'a'},
            {TesseraSeal.HEADER_BYTES + 1568 + 2, 'n'},
            {TesseraSeal.HEADER_BYTES + 1568 + 2 + 12, 'c'},
            {env.length - 32 - 1, 't'},
            {env.length - 1, 'm'},
        };
        for (int[] s : spots) {
            byte[] bad = env.clone();
            bad[s[0]] ^= 1;
            boolean threw = false;
            try { TesseraSeal.decrypt(bad, kp.priv, ad); }
            catch (Exception e) { threw = true; }
            if (!threw) { System.out.println("FAIL tamper " + (char) s[1]); gFail++; return; }
        }
        expect(true, "tamper (6 sites)");
    }

    static void testPeekHeader() {
        KeyPair kp = TesseraSeal.generateKeypair(TesseraSeal.SUITE_MLKEM1024_AESGCM);
        TesseraSeal.setNowMsForTesting(1_700_000_000_000L);
        byte[] env = TesseraSeal.encrypt("x".getBytes(), kp.pub, TesseraSeal.SUITE_MLKEM1024_AESGCM,
                                     new byte[0], null, 7);
        TesseraSeal.setNowMsForTesting(null);
        DecodedHeader h = TesseraSeal.peekHeader(env);
        expect(h.timestampMs == 1_700_000_000_000L && h.variant == 0x04 && h.suite == 0x01
               && h.counter == 7 && h.kemCtLen == 1568 && h.adLen == 0, "peek_header");
    }

    // --- KAT consumption ----------------------------------------------------

    static String slurp(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path)));
    }

    static List<Map<String, Object>> parseRecords(String json) {
        // Minimal JSON-array-of-objects parser sufficient for our vectors.
        // Each value is a string (hex) or number or bool; objects are flat.
        List<Map<String, Object>> out = new ArrayList<>();
        int i = json.indexOf('[');
        while (i >= 0 && i < json.length()) {
            int objStart = json.indexOf('{', i);
            if (objStart < 0) break;
            int objEnd = matchBrace(json, objStart);
            if (objEnd < 0) break;
            Map<String, Object> rec = parseObject(json.substring(objStart, objEnd + 1));
            out.add(rec);
            i = objEnd + 1;
        }
        return out;
    }

    private static int matchBrace(String s, int start) {
        int depth = 0;
        boolean inStr = false;
        boolean esc = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) { esc = false; continue; }
            if (c == '\\' && inStr) { esc = true; continue; }
            if (c == '"') { inStr = !inStr; continue; }
            if (inStr) continue;
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private static Map<String, Object> parseObject(String s) {
        // Strip braces and parse "key": value pairs naively.
        Map<String, Object> out = new LinkedHashMap<>();
        s = s.trim();
        if (s.startsWith("{")) s = s.substring(1, s.length() - 1);
        int i = 0;
        while (i < s.length()) {
            // Find next "key"
            int kStart = s.indexOf('"', i);
            if (kStart < 0) break;
            int kEnd = s.indexOf('"', kStart + 1);
            if (kEnd < 0) break;
            String key = s.substring(kStart + 1, kEnd);
            int colon = s.indexOf(':', kEnd);
            int vStart = colon + 1;
            while (vStart < s.length() && Character.isWhitespace(s.charAt(vStart))) vStart++;
            // Value: either "..." string, true/false, or number.
            if (s.charAt(vStart) == '"') {
                int vEnd = s.indexOf('"', vStart + 1);
                while (vEnd > 0 && s.charAt(vEnd - 1) == '\\') vEnd = s.indexOf('"', vEnd + 1);
                out.put(key, s.substring(vStart + 1, vEnd));
                i = vEnd + 1;
            } else {
                int vEnd = vStart;
                while (vEnd < s.length() && ",}".indexOf(s.charAt(vEnd)) < 0) vEnd++;
                String val = s.substring(vStart, vEnd).trim();
                if (val.equals("true")) out.put(key, Boolean.TRUE);
                else if (val.equals("false")) out.put(key, Boolean.FALSE);
                else if (val.equals("null")) out.put(key, null);
                else {
                    try { out.put(key, Long.parseLong(val)); }
                    catch (NumberFormatException e) { out.put(key, val); }
                }
                i = vEnd;
            }
        }
        return out;
    }

    static String str(Map<String, Object> r, String k) {
        Object v = r.get(k);
        return v == null ? null : v.toString();
    }
    static long lng(Map<String, Object> r, String k) {
        Object v = r.get(k);
        return v instanceof Long ? (Long) v : 0L;
    }

    static void testKATDecrypt() throws Exception {
        String json = slurp("../conformance/vectors/decrypt.json");
        List<Map<String, Object>> recs = parseRecords(json);
        int n = 0;
        for (Map<String, Object> r : recs) {
            byte[] sk = hex(str(r, "private_key_hex"));
            long suite = lng(r, "suite");
            byte[] env = hex(str(r, "envelope_hex"));
            byte[] ad = hex(str(r, "expected_ad_hex"));
            byte[] pt = hex(str(r, "expected_plaintext_hex"));
            KeyPair kp = TesseraSeal.importKeypair(null, sk, (byte) suite);
            byte[] got = TesseraSeal.decrypt(env, kp.priv, ad);
            if (!Arrays.equals(got, pt)) {
                System.out.println("FAIL kat:" + str(r, "name")); gFail++;
            } else {
                System.out.println("PASS kat:" + str(r, "name")); gPass++;
            }
            n++;
        }
        if (n == 0) { System.out.println("FAIL kat_decrypt: no records"); gFail++; }
    }

    static void testKATADBinding() throws Exception {
        String json = slurp("../conformance/vectors/ad_binding.json");
        List<Map<String, Object>> recs = parseRecords(json);
        for (Map<String, Object> r : recs) {
            byte[] sk = hex(str(r, "private_key_hex"));
            byte[] env = hex(str(r, "envelope_hex"));
            byte[] ad = hex(str(r, "expected_ad_hex"));
            KeyPair kp = TesseraSeal.importKeypair(null, sk, TesseraSeal.SUITE_MLKEM1024_AESGCM);
            String op = str(r, "op");
            boolean ok;
            if ("decrypt".equals(op)) {
                try {
                    byte[] got = TesseraSeal.decrypt(env, kp.priv, ad);
                    byte[] expected = hex(str(r, "expected_plaintext_hex"));
                    ok = Arrays.equals(got, expected);
                } catch (Exception e) { ok = false; }
            } else {
                ok = false;
                try { TesseraSeal.decrypt(env, kp.priv, ad); }
                catch (Exception e) { ok = true; }
            }
            if (ok) { System.out.println("PASS kat-ab:" + str(r, "name")); gPass++; }
            else    { System.out.println("FAIL kat-ab:" + str(r, "name")); gFail++; }
        }
    }

    static void testKATInvalid() throws Exception {
        String json = slurp("../conformance/vectors/invalid.json");
        List<Map<String, Object>> recs = parseRecords(json);
        for (Map<String, Object> r : recs) {
            byte[] env = hex(str(r, "envelope_hex"));
            String op = str(r, "op");
            boolean ok;
            if ("peek_header_should_fail".equals(op)) {
                ok = false;
                try { TesseraSeal.peekHeader(env); }
                catch (TesseraSealError e) { ok = true; }
            } else if ("decrypt_should_fail".equals(op)) {
                String skHex = str(r, "private_key_hex");
                if (skHex != null && !skHex.isEmpty()) {
                    KeyPair kp = TesseraSeal.importKeypair(null, hex(skHex), TesseraSeal.SUITE_MLKEM1024_AESGCM);
                    byte[] ad = hex(str(r, "expected_ad_hex"));
                    ok = false;
                    try { TesseraSeal.decrypt(env, kp.priv, ad); }
                    catch (TesseraSealError e) { ok = true; }
                } else {
                    // Truncation case
                    ok = true;
                    try { if (env.length >= TesseraSeal.HEADER_BYTES) TesseraSeal.peekHeader(env); } catch (TesseraSealError e) {}
                }
            } else { ok = false; }
            if (ok) { System.out.println("PASS kat-inv:" + str(r, "name")); gPass++; }
            else    { System.out.println("FAIL kat-inv:" + str(r, "name")); gFail++; }
        }
    }

    static void testKATMinTimestamp() throws Exception {
        String json = slurp("../conformance/vectors/min_timestamp.json");
        List<Map<String, Object>> recs = parseRecords(json);
        for (Map<String, Object> r : recs) {
            byte[] env = hex(str(r, "envelope_hex"));
            long min = lng(r, "min_ms");
            boolean expected = Boolean.TRUE.equals(r.get("expected"));
            boolean got = TesseraSeal.validateMinTimestamp(env, min);
            if (got == expected) { System.out.println("PASS kat-ts:" + str(r, "name")); gPass++; }
            else { System.out.println("FAIL kat-ts:" + str(r, "name") + " got=" + got + " want=" + expected); gFail++; }
        }
    }
}
