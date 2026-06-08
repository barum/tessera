use std::time::Instant;
use tessera_id::{TesseraId, StandardGenerator, HlcGenerator};

fn bench<F: FnMut()>(name: &str, n: u64, mut f: F) {
    // Warmup
    for _ in 0..10_000 { f(); }
    let mut best = 0.0f64;
    for _ in 0..5 {
        let t0 = Instant::now();
        for _ in 0..n { f(); }
        let elapsed = t0.elapsed().as_secs_f64();
        let ops = n as f64 / elapsed;
        if ops > best { best = ops; }
    }
    println!("{:<40} {:>14.0} ops/sec   ({:>6.0} ns/op)",
             name, best, 1e9 / best);
}

fn main() {
    println!("TesseraID Rust benchmarks (release build)\n");
    println!("{:-<70}", "");

    // Standard generator (raw, no lock).
    {
        let mut g = StandardGenerator::new();
        bench("Standard generator (raw)", 1_000_000, || {
            std::hint::black_box(g.new_id().unwrap());
        });
    }

    // Standard via thread-local default (locked).
    bench("Standard via TesseraId::new()", 1_000_000, || {
        std::hint::black_box(TesseraId::new());
    });

    // HLC raw.
    {
        let mut g = HlcGenerator::new();
        bench("HLC generator (raw)", 1_000_000, || {
            std::hint::black_box(g.new_id(None).unwrap());
        });
    }

    // HLC via thread-local.
    bench("HLC via TesseraId::new_hlc()", 1_000_000, || {
        std::hint::black_box(TesseraId::new_hlc(None).unwrap());
    });

    // Encoding.
    let id = TesseraId::new();
    bench("encode Base64URL", 5_000_000, || {
        std::hint::black_box(id.to_base64url());
    });
    bench("encode Crockford Base32", 5_000_000, || {
        std::hint::black_box(id.to_crockford());
    });

    let s64 = id.to_base64url();
    let s32 = id.to_crockford();
    bench("decode Base64URL", 5_000_000, || {
        std::hint::black_box(TesseraId::from_base64url(&s64).unwrap());
    });
    bench("decode Crockford Base32", 5_000_000, || {
        std::hint::black_box(TesseraId::from_crockford(&s32).unwrap());
    });
}
