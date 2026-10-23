//! Writes conformance/vectors/ff1.json (FF1 FIPS-mode PRP vectors) from the context key.
//! The FF1 core itself is pinned to NIST SP 800-38G samples 7-9 in src/ff1.rs.

use tessera_mark::{AssetKey, Mark, Profile, PrpMode};

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let dir = format!("{}/../conformance/vectors", env!("CARGO_MANIFEST_DIR"));
    let ctx = std::fs::read_to_string(format!("{dir}/context.json")).unwrap();
    let field = |k: &str| {
        let i = ctx.find(&format!("\"{k}\": \"")).unwrap() + k.len() + 5;
        ctx[i..i + ctx[i..].find('"').unwrap()].to_string()
    };
    let key = AssetKey::derive(
        &h(&field("master_key_hex")),
        field("tenant").as_bytes(),
        &h(&field("asset_id_hex")),
        &h(&field("asset_hash_hex")),
    )
    .unwrap();
    let mut rows = Vec::new();
    for p in Profile::ALL {
        let m = Mark::with_mode(&key, p, PrpMode::Ff1);
        for idx in [0, 1, 2, 1000, p.max_code()] {
            let code = m.encode_index(idx).unwrap();
            rows.push(format!(
                "  {{\n    \"name\": \"ff1_{}_index_{idx}\",\n    \"op\": \"allocate_ff1\",\n    \"profile\": \"{}\",\n    \"index\": {idx},\n    \"code\": {code}\n  }}",
                p.name().to_lowercase(),
                p.name()
            ));
        }
    }
    std::fs::write(
        format!("{dir}/ff1.json"),
        format!("[\n{}\n]\n", rows.join(",\n")),
    )
    .unwrap();
    println!("wrote {} FF1 vectors", rows.len());
}
