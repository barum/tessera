//! Conformance: checks the Rust implementation against tessera-mark/conformance/vectors.

use serde_json::Value;
use tessera_mark::*;

fn load(name: &str) -> Value {
    let p = format!(
        "{}/../conformance/vectors/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn key() -> (AssetKey, Vec<u8>) {
    let c = load("context");
    let k = AssetKey::derive(
        &h(&c["master_key_hex"]),
        c["tenant"].as_str().unwrap().as_bytes(),
        &h(&c["asset_id_hex"]),
        &h(&c["asset_hash_hex"]),
    )
    .unwrap();
    assert_eq!(k.as_bytes().to_vec(), h(&c["asset_key_hex"]));
    assert_eq!(
        asset_tag(&h(&c["asset_id_hex"])).to_vec(),
        h(&c["asset_tag_hex"])
    );
    (k, h(&c["asset_id_hex"]))
}

#[test]
fn allocate_vectors() {
    let (k, asset) = key();
    let vs = load("allocate");
    assert_eq!(vs.as_array().unwrap().len(), 25);
    for v in vs.as_array().unwrap() {
        let p = Profile::from_name(v["profile"].as_str().unwrap()).unwrap();
        let m = Mark::new(&k, p);
        let e = &v["expected"];
        let idx = v["index"].as_u64().unwrap();
        let code = m.encode_index(idx).unwrap();
        let name = v["name"].as_str().unwrap();
        assert_eq!(code, e["code"].as_u64().unwrap(), "{name}");
        assert_eq!(m.decode_code(code).unwrap(), idx, "{name}");
        assert_eq!(m.check(code), e["check"].as_u64().unwrap(), "{name}");
        let word: u128 = e["channel_word"].to_string().parse().unwrap();
        assert_eq!(m.channel_word(code), word, "{name}");
        assert_eq!(
            to_text(p, code).unwrap(),
            e["text"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(from_text(e["text"].as_str().unwrap()).unwrap(), (p, code));
        let rec = Record::new(&asset, p, code).unwrap();
        assert_eq!(rec.to_bytes().to_vec(), h(&e["record_hex"]), "{name}");
        assert_eq!(Record::from_bytes(&rec.to_bytes()).unwrap().code(), code);
        assert_eq!(
            m.binding(code, &h(&v["session_id_hex"])).to_vec(),
            h(&e["binding_hex"]),
            "{name}"
        );
        let segs: Vec<u8> = e["segments_0_15"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(m.sequence(code, 0, 16), segs, "{name}");
    }
}

#[test]
fn invalid_vectors() {
    for v in load("invalid").as_array().unwrap() {
        let err = Record::from_bytes(&h(&v["input_hex"])).unwrap_err();
        assert_eq!(err.code(), v["error"].as_str().unwrap(), "{}", v["name"]);
    }
}

#[test]
fn ff1_mode_vectors() {
    let (k, _) = key();
    for v in load("ff1").as_array().unwrap() {
        let p = Profile::from_name(v["profile"].as_str().unwrap()).unwrap();
        let m = Mark::with_mode(&k, p, PrpMode::Ff1);
        let idx = v["index"].as_u64().unwrap();
        let code = m.encode_index(idx).unwrap();
        assert_eq!(code, v["code"].as_u64().unwrap(), "{}", v["name"]);
        assert_eq!(m.decode_code(code).unwrap(), idx);
    }
}

#[test]
fn round_trip_and_uniqueness() {
    let (k, _) = key();
    for mode in [PrpMode::Kmac, PrpMode::Ff1] {
        let m = Mark::with_mode(&k, Profile::Tm24, mode);
        let mut seen = std::collections::HashSet::new();
        for i in 0..4096u64 {
            let c = m.encode_index(i).unwrap();
            assert!(seen.insert(c));
            assert_eq!(m.decode_code(c).unwrap(), i);
        }
        assert_eq!(m.encode_index(1 << 24), Err(MarkError::IndexRange));
        assert_eq!(m.decode_code(1 << 24), Err(MarkError::CodeRange));
    }
}

#[test]
fn decode_observations_with_noise_and_erasures() {
    let (k, _) = key();
    let m = Mark::new(&k, Profile::Tm32);
    let code = m.encode_index(4242).unwrap();
    let mut obs: Vec<(u64, u8)> = (0..144).map(|s| (s, m.segment_variant(code, s))).collect();
    obs[5].1 ^= 1; // one flipped bit, outvoted by the other two cycles
    let d = m.decode_observations(&obs).unwrap();
    assert_eq!((d.code, d.index, d.erasures), (code, 4242, 0));
    // Drop three positions entirely: they become erasures resolved by the check tag.
    let partial: Vec<(u64, u8)> = obs
        .iter()
        .copied()
        .filter(|(s, _)| ![1, 2, 3].contains(&(s % 48)))
        .collect();
    assert_eq!(m.decode_observations(&partial).unwrap().erasures, 3);
    let few: Vec<(u64, u8)> = obs[..40].to_vec();
    assert_eq!(m.decode_observations(&few), Err(MarkError::TooManyErasures));
    let other = Mark::new(&AssetKey::from_bytes([9; 32]), Profile::Tm32);
    assert!(other.decode_observations(&obs).is_err());
    let ranked = m.score_candidates(&obs, &[m.encode_index(1).unwrap(), code]);
    assert_eq!(ranked[0], (143, code));
}

#[test]
fn text_errors_and_probability() {
    assert_eq!(from_text("TM32-0000000"), Err(MarkError::BadText));
    assert_eq!(from_text("TM99-0000000-0"), Err(MarkError::BadText));
    let t = to_text(Profile::Tm32, 7).unwrap();
    let mut bad = t.clone();
    let last = if bad.ends_with('0') { '1' } else { '0' };
    bad.pop();
    bad.push(last);
    assert_eq!(from_text(&bad), Err(MarkError::BadCheck));
    assert_eq!(from_text(&t.to_lowercase()).unwrap(), (Profile::Tm32, 7));
    assert!(false_match_probability(1_000_000, 200, 190) < 1e-9);
    assert!(false_match_probability(1_000_000, 48, 30) > 1e-9);
    assert_eq!(false_match_probability(1, 10, 0), 1.0);
    assert!(AssetKey::derive(&[0; 31], b"t", b"a", b"").is_err());
}
