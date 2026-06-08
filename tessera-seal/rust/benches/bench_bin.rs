//! Custom-time benchmarks for the Rust TesseraSeal reference.
//!
//! Run with:
//!     cd tessera-seal/rust && cargo run --release --bin tessera-seal-bench

use std::time::Instant;

use tessera_seal::{
    decrypt, encrypt, generate_keypair, peek_header,
    SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA,
    SUITE_HYBRID_X25519_MLKEM1024_AESGCM,
};

fn bench<F: FnMut()>(name: &str, n: u64, mut f: F) {
    for _ in 0..200 { f(); }
    let mut best = 0.0f64;
    for _ in 0..3 {
        let t0 = Instant::now();
        for _ in 0..n { f(); }
        let elapsed = t0.elapsed().as_secs_f64();
        let ops = n as f64 / elapsed;
        if ops > best { best = ops; }
    }
    println!("{:<40} {:>14.0} ops/sec   ({:>10.0} ns/op)",
             name, best, 1e9 / best);
}

fn main() {
    println!("TesseraSeal Rust benchmarks (release build, RustCrypto ml-kem 0.3 + aes-gcm 0.10)");
    println!("{:-<70}", "");

    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let pt_1kb = vec![0u8; 1024];
    let pt_1mb = vec![0u8; 1024 * 1024];
    let env_1kb = encrypt(&pt_1kb, &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap();
    let env_1mb = encrypt(&pt_1mb, &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap();

    bench("keygen (ML-KEM-1024)", 2_000, || {
        std::hint::black_box(generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap());
    });
    bench("encrypt_1KB (AES-256-GCM)", 5_000, || {
        std::hint::black_box(encrypt(&pt_1kb, &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap());
    });
    bench("decrypt_1KB (AES-256-GCM)", 5_000, || {
        std::hint::black_box(decrypt(&env_1kb, &priv_k, &[]).unwrap());
    });
    bench("encrypt_1MB (AES-256-GCM)", 200, || {
        std::hint::black_box(encrypt(&pt_1mb, &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap());
    });
    bench("decrypt_1MB (AES-256-GCM)", 200, || {
        std::hint::black_box(decrypt(&env_1mb, &priv_k, &[]).unwrap());
    });
    bench("peek_header", 5_000_000, || {
        std::hint::black_box(peek_header(&env_1kb).unwrap());
    });

    let (priv_c, pub_c) = generate_keypair(SUITE_MLKEM1024_CHACHA).unwrap();
    let env_1kb_c = encrypt(&pt_1kb, &pub_c, SUITE_MLKEM1024_CHACHA, &[], None, 0).unwrap();
    bench("encrypt_1KB (ChaCha20-Poly1305)", 5_000, || {
        std::hint::black_box(encrypt(&pt_1kb, &pub_c, SUITE_MLKEM1024_CHACHA, &[], None, 0).unwrap());
    });
    bench("decrypt_1KB (ChaCha20-Poly1305)", 5_000, || {
        std::hint::black_box(decrypt(&env_1kb_c, &priv_c, &[]).unwrap());
    });

    // Hybrid suite 0x06 (X25519 + ML-KEM-1024 + AES-256-GCM + UtC). Cost is
    // ML-KEM baseline + one X25519 keygen and one DH per envelope (~30 µs).
    let (priv_h, pub_h) = generate_keypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM).unwrap();
    let env_1kb_h = encrypt(&pt_1kb, &pub_h, SUITE_HYBRID_X25519_MLKEM1024_AESGCM, &[], None, 0).unwrap();
    bench("keygen (hybrid X25519+ML-KEM-1024)", 2_000, || {
        std::hint::black_box(generate_keypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM).unwrap());
    });
    bench("encrypt_1KB (hybrid suite 0x06)", 5_000, || {
        std::hint::black_box(encrypt(&pt_1kb, &pub_h, SUITE_HYBRID_X25519_MLKEM1024_AESGCM, &[], None, 0).unwrap());
    });
    bench("decrypt_1KB (hybrid suite 0x06)", 5_000, || {
        std::hint::black_box(decrypt(&env_1kb_h, &priv_h, &[]).unwrap());
    });
}
