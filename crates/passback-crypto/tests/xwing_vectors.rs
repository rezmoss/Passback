//! X-Wing known-answer tests from draft-connolly-cfrg-xwing-kem (spec/test-vectors.txt).

use passback_crypto::{Key32, kem::KemSecretKey};

fn parse(text: &str) -> Vec<Vec<(String, Vec<u8>)>> {
    let mut cases = Vec::new();
    let mut cur: Vec<(String, Vec<u8>)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            let mut it = line.split_whitespace();
            let key = it.next().unwrap().to_string();
            if key == "seed" && !cur.is_empty() {
                cases.push(std::mem::take(&mut cur));
            }
            let hex_part: String = it.collect();
            cur.push((key, hex::decode(hex_part).unwrap()));
        } else {
            let last = cur.last_mut().unwrap();
            last.1.extend(hex::decode(line.trim()).unwrap());
        }
    }
    cases.push(cur);
    cases
}

#[test]
fn xwing_known_answers() {
    let cases = parse(include_str!("vectors/xwing-draft.txt"));
    assert!(!cases.is_empty());
    for case in &cases {
        let get = |k: &str| case.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        let sk = KemSecretKey::from_seed(Key32::from_slice(&get("sk")).unwrap());
        assert_eq!(sk.public().as_bytes(), &get("pk")[..], "public key");
        let eseed = get("eseed");
        let (ct, ss) = sk
            .public()
            .encapsulate_derand(eseed[..32].try_into().unwrap(), eseed[32..].try_into().unwrap())
            .unwrap();
        assert_eq!(ct, get("ct"), "ciphertext");
        assert_eq!(&ss.expose()[..], &get("ss")[..], "shared secret");
        assert_eq!(sk.decapsulate(&ct).unwrap().expose(), ss.expose());
    }
    eprintln!("{} X-Wing vectors ok", cases.len());
}
