package com.tessera.hash;

import com.tessera.common.Keccak;

import java.util.Arrays;

/**
 * TesseraHash — Post-Quantum Content Identifier.
 *
 * 73-byte sortable content identifier with a 512-bit SHAKE-256 tail.
 * Variant byte 0x03. Sibling to TesseraID, NOT a hash function.
 */
public final class TesseraHash implements Comparable<TesseraHash> {

    public static final int SIZE_BYTES = 73;
    public static final int TAIL_BYTES = 64;
    public static final int TAIL_OFFSET = 9;
    public static final byte VARIANT = 0x03;
    public static final int ENCODED_LENGTH_B64 = 98;
    public static final int ENCODED_LENGTH_B32 = 117;
    public static final long MIN_TIMESTAMP_MS = 1_700_000_000_000L;

    private final byte[] bytes;

    public TesseraHash(byte[] bytes) {
        if (bytes == null || bytes.length != SIZE_BYTES) {
            throw new IllegalArgumentException("TesseraHash must be exactly 73 bytes");
        }
        if (bytes[6] != VARIANT) {
            throw new IllegalArgumentException(
                "TesseraHash variant must be 0x03, got 0x" + String.format("%02X", bytes[6]));
        }
        this.bytes = Arrays.copyOf(bytes, SIZE_BYTES);
    }

    /** Stateless: returns the 64-byte SHAKE-256 digest of content. */
    public static byte[] hashOnly(byte[] content) {
        return Keccak.shake256(content, TAIL_BYTES);
    }

    /** Construct a TesseraHash with explicit (timestamp_ms, counter). */
    public static TesseraHash hashAt(byte[] content, long timestampMs, int counter) {
        if (timestampMs < 0 || timestampMs > ((1L << 48) - 1)) {
            throw new IllegalArgumentException("timestamp_ms out of range");
        }
        if (counter < 0 || counter > 0xFFFF) {
            throw new IllegalArgumentException("counter out of range");
        }
        byte[] raw = new byte[SIZE_BYTES];
        raw[0] = (byte)((timestampMs >>> 40) & 0xFF);
        raw[1] = (byte)((timestampMs >>> 32) & 0xFF);
        raw[2] = (byte)((timestampMs >>> 24) & 0xFF);
        raw[3] = (byte)((timestampMs >>> 16) & 0xFF);
        raw[4] = (byte)((timestampMs >>>  8) & 0xFF);
        raw[5] = (byte)( timestampMs         & 0xFF);
        raw[6] = VARIANT;
        raw[7] = (byte)((counter >>> 8) & 0xFF);
        raw[8] = (byte)( counter        & 0xFF);
        byte[] tail = Keccak.shake256(content, TAIL_BYTES);
        System.arraycopy(tail, 0, raw, TAIL_OFFSET, TAIL_BYTES);
        return new TesseraHash(raw);
    }

    /** Returns a defensive copy of the 73 wire bytes. */
    public byte[] toBytes() {
        return Arrays.copyOf(bytes, SIZE_BYTES);
    }

    /** Internal accessor used by the codec and conformance tooling to avoid repeated copies. Length 73, do not mutate. */
    public byte[] bytesNoCopy() {
        return bytes;
    }

    public long timestampMs() {
        return  ((long)(bytes[0] & 0xFF) << 40)
              | ((long)(bytes[1] & 0xFF) << 32)
              | ((long)(bytes[2] & 0xFF) << 24)
              | ((long)(bytes[3] & 0xFF) << 16)
              | ((long)(bytes[4] & 0xFF) << 8)
              |  (long)(bytes[5] & 0xFF);
    }

    public byte variant() { return bytes[6]; }

    public int counter() {
        return ((bytes[7] & 0xFF) << 8) | (bytes[8] & 0xFF);
    }

    public byte[] tail() {
        return Arrays.copyOfRange(bytes, TAIL_OFFSET, SIZE_BYTES);
    }

    /** Constant-time verify of the tail against SHAKE-256(content). */
    public boolean verify(byte[] content) {
        byte[] expected = Keccak.shake256(content, TAIL_BYTES);
        int diff = 0;
        for (int i = 0; i < TAIL_BYTES; ++i) {
            diff |= (bytes[TAIL_OFFSET + i] ^ expected[i]) & 0xFF;
        }
        return diff == 0;
    }

    public boolean validateMinTimestamp() {
        return timestampMs() >= MIN_TIMESTAMP_MS;
    }

    @Override
    public int compareTo(TesseraHash other) {
        return Arrays.compareUnsigned(this.bytes, other.bytes);
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof TesseraHash p) && Arrays.equals(this.bytes, p.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return TesseraHashCodec.encodeBase64Url(this);
    }
}
