package com.tessera.id;

import java.util.Arrays;

/**
 * Immutable TesseraID value. Holds the 41-byte wire form. Use {@link StandardGenerator}
 * or {@link HLCGenerator} to produce instances; use {@link Codec} for encode/decode.
 *
 * <p>Layout (matches the spec):
 * <pre>
 *   offsets 0..5  : 48-bit big-endian millisecond timestamp
 *   offset  6     : variant byte (0x01 = Standard, 0x02 = HLC)
 *   offsets 7..8  : 16-bit big-endian counter
 *   offsets 9..40 : 256-bit random tail
 * </pre>
 */
public final class TesseraId implements Comparable<TesseraId> {
    public static final int SIZE_BYTES = 41;
    public static final byte VARIANT_STANDARD = 0x01;
    public static final byte VARIANT_HLC = 0x02;

    /** Project epoch — optional, non-normative defensive bound. The standard
     *  constructor accepts all timestamps; validateMinTimestamp() returns
     *  true only for TesseraIDs at or after this. */
    public static final long MIN_TIMESTAMP_MS = 1_700_000_000_000L;

    /** Non-normative defensive check: timestampMs() &gt;= MIN_TIMESTAMP_MS. */
    public boolean validateMinTimestamp() {
        return timestampMs() >= MIN_TIMESTAMP_MS;
    }

    private final byte[] bytes; // length 41, defensively copied at construction

    public TesseraId(byte[] bytes) {
        if (bytes == null || bytes.length != SIZE_BYTES) {
            throw new IllegalArgumentException("TesseraID must be exactly 41 bytes");
        }
        byte v = bytes[6];
        if (v != VARIANT_STANDARD && v != VARIANT_HLC) {
            throw new IllegalArgumentException("Invalid variant byte: 0x" + String.format("%02X", v));
        }
        this.bytes = Arrays.copyOf(bytes, SIZE_BYTES);
    }

    /** Returns a defensive copy of the 41 wire bytes. */
    public byte[] toBytes() {
        return Arrays.copyOf(bytes, SIZE_BYTES);
    }

    /** Internal accessor used by the codec and conformance tooling to avoid repeated copies. Length 41, do not mutate. */
    public byte[] bytesNoCopy() {
        return bytes;
    }

    /** Milliseconds since the Unix epoch, decoded from the 48-bit big-endian timestamp. */
    public long timestampMs() {
        return  ((long)(bytes[0] & 0xFF) << 40)
              | ((long)(bytes[1] & 0xFF) << 32)
              | ((long)(bytes[2] & 0xFF) << 24)
              | ((long)(bytes[3] & 0xFF) << 16)
              | ((long)(bytes[4] & 0xFF) << 8)
              |  (long)(bytes[5] & 0xFF);
    }

    /** 0x01 (Standard) or 0x02 (HLC). */
    public byte variant() {
        return bytes[6];
    }

    /** 16-bit unsigned counter. */
    public int counter() {
        return ((bytes[7] & 0xFF) << 8) | (bytes[8] & 0xFF);
    }

    @Override
    public int compareTo(TesseraId other) {
        // Lexicographic byte comparison — preserves time ordering by construction.
        return Arrays.compareUnsigned(this.bytes, other.bytes);
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof TesseraId p) && Arrays.equals(this.bytes, p.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return Codec.encodeBase64Url(this);
    }
}
