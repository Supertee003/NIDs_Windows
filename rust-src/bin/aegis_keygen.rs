// aegis-keygen: offline operator key ceremony for policy signing.
//
// Generates Ed25519 keys, signs policy files into v1 sidecars, and
// verifies them — everything the daemon's observe-only path and the
// (future, opt-in) trusted path consume. RUN OFFLINE on a trusted
// host. The repo never stores keys; this tool never touches the
// network, the daemon, or enforcement. Private seed material exists
// only in operator hands (argv/env/file the operator provides).
//
// Usage:
//   aegis-keygen genkey [--seed <64-hex>]      prints pubkey hex (and seed hex when generated)
//   aegis-keygen sign --seed <64-hex> --key-id <u32> --in <file> --out <sidecar.json>
//   aegis-keygen verify --pub <64-hex> --in <file> --sidecar <sidecar.json>
// Exit: 0 ok (verify: valid), 1 usage/IO/crypto error, 2 invalid signature.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::process::ExitCode;

fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected 64 lowercase hex chars".to_string());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    Ok(out)
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  aegis-keygen genkey [--seed <64-hex>]");
    eprintln!("  aegis-keygen sign --seed <64-hex> --key-id <u32> --in <file> --out <sidecar.json>");
    eprintln!("  aegis-keygen verify --pub <64-hex> --in <file> --sidecar <sidecar.json>");
    ExitCode::from(1)
}

fn cmd_genkey(args: &[String]) -> ExitCode {
    let seed_hex = match arg_value(args, "--seed") {
        Some(s) => s,
        None => {
            // Fresh randomness from the OS; printed once for the operator
            // to store offline. Never written to disk by this tool.
            let mut seed = [0u8; 32];
            use ring::rand::SecureRandom;
            if SystemRandom::new().fill(&mut seed).is_err() {
                eprintln!("genkey: RNG failure");
                return ExitCode::from(1);
            }
            let seed_hex = hex_of(&seed);
            println!("seed: {seed_hex}");
            seed_hex
        }
    };
    let seed = match hex_to_32(&seed_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("genkey: bad seed: {e}");
            return ExitCode::from(1);
        }
    };
    let key_pair = match Ed25519KeyPair::from_seed_unchecked(&seed) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("genkey: keypair: {e:?}");
            return ExitCode::from(1);
        }
    };
    println!("pub: {}", hex_of(key_pair.public_key().as_ref()));
    ExitCode::SUCCESS
}

fn cmd_sign(args: &[String]) -> ExitCode {
    let (Some(seed_hex), Some(key_id_raw), Some(in_path), Some(out_path)) = (
        arg_value(args, "--seed"),
        arg_value(args, "--key-id"),
        arg_value(args, "--in"),
        arg_value(args, "--out"),
    ) else {
        return usage();
    };
    let key_id: u32 = match key_id_raw.parse::<u32>().ok().filter(|v| *v != 0) {
        Some(v) => v,
        None => {
            eprintln!("sign: --key-id must be a non-zero u32");
            return ExitCode::from(1);
        }
    };
    let seed = match hex_to_32(&seed_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sign: bad seed: {e}");
            return ExitCode::from(1);
        }
    };
    let data = match std::fs::read(&in_path) {
        Ok(d) if !d.is_empty() => d,
        _ => {
            eprintln!("sign: cannot read non-empty input {in_path}");
            return ExitCode::from(1);
        }
    };
    let key_pair = match Ed25519KeyPair::from_seed_unchecked(&seed) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sign: keypair: {e:?}");
            return ExitCode::from(1);
        }
    };
    let sig = key_pair.sign(&data);
    let digest = ring::digest::digest(&ring::digest::SHA256, &data);
    let sidecar = format!(
        "{{\n  \"version\": 1,\n  \"key_id\": {key_id},\n  \"ed25519_sig_hex\": \"{}\",\n  \"ir_sha256_hex\": \"{}\"\n}}\n",
        hex_of(sig.as_ref()),
        hex_of(digest.as_ref()),
    );
    if std::fs::write(&out_path, sidecar).is_err() {
        eprintln!("sign: cannot write {out_path}");
        return ExitCode::from(1);
    }
    println!("signed {in_path} -> {out_path} (key_id {key_id})");
    ExitCode::SUCCESS
}

fn cmd_verify(args: &[String]) -> ExitCode {
    let (Some(pub_hex), Some(in_path), Some(sidecar_path)) = (
        arg_value(args, "--pub"),
        arg_value(args, "--in"),
        arg_value(args, "--sidecar"),
    ) else {
        return usage();
    };
    let pubkey = match hex_to_32(&pub_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("verify: bad pubkey: {e}");
            return ExitCode::from(1);
        }
    };
    let data = match std::fs::read(&in_path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("verify: cannot read {in_path}");
            return ExitCode::from(1);
        }
    };
    let sidecar_raw = match std::fs::read_to_string(&sidecar_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("verify: cannot read {sidecar_path}");
            return ExitCode::from(1);
        }
    };
    // Minimal strict parse (no serde dependency for two fields).
    let sig_hex = match extract_json_string(&sidecar_raw, "ed25519_sig_hex") {
        Some(s) if s.len() == 128 => s,
        _ => {
            eprintln!("verify: sidecar missing 128-hex ed25519_sig_hex");
            return ExitCode::from(2);
        }
    };
    let sig_bytes: Vec<u8> = (0..64)
        .map(|i| u8::from_str_radix(&sig_hex[2 * i..2 * i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .unwrap_or_default();
    if sig_bytes.len() != 64 {
        eprintln!("verify: bad signature encoding");
        return ExitCode::from(2);
    }
    let peer = UnparsedPublicKey::new(&ED25519, pubkey);
    match peer.verify(&data, &sig_bytes) {
        Ok(()) => {
            println!("VALID: {in_path}");
            ExitCode::SUCCESS
        }
        Err(_) => {
            println!("INVALID: {in_path}");
            ExitCode::from(2)
        }
    }
}

/// Extract a top-level JSON string field value (strict quotes, no escapes
/// needed for hex payloads). Returns None when absent or malformed.
fn extract_json_string(doc: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = doc.find(&needle)?;
    let rest = doc[at + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return usage();
    }
    match args[0].as_str() {
        "genkey" => cmd_genkey(&args[1..]),
        "sign" => cmd_sign(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn test_pub() -> [u8; 32] {
        let seed = hex_to_32(TEST_SEED).unwrap();
        Ed25519KeyPair::from_seed_unchecked(&seed)
            .unwrap()
            .public_key()
            .as_ref()
            .try_into()
            .unwrap()
    }

    #[test]
    fn ceremony_roundtrip_sign_then_verify() {
        let dir = std::env::temp_dir();
        let base = format!("aegis-ceremony-{}", std::process::id());
        let in_path = dir.join(format!("{base}.json"));
        let out_path = dir.join(format!("{base}.sig.json"));
        std::fs::write(&in_path, b"{\"magic\":1347374129}").unwrap();
        let args = vec![
            "--seed".to_string(), TEST_SEED.to_string(),
            "--key-id".to_string(), "7".to_string(),
            "--in".to_string(), in_path.to_string_lossy().into_owned(),
            "--out".to_string(), out_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(cmd_sign(&args), ExitCode::SUCCESS);
        let pub_hex = hex_of(&test_pub());
        let args = vec![
            "--pub".to_string(), pub_hex,
            "--in".to_string(), in_path.to_string_lossy().into_owned(),
            "--sidecar".to_string(), out_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(cmd_verify(&args), ExitCode::SUCCESS);
        std::fs::remove_file(&in_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    #[test]
    fn ceremony_verify_rejects_tampered_and_wrong_key() {
        let dir = std::env::temp_dir();
        let base = format!("aegis-ceremony-neg-{}", std::process::id());
        let in_path = dir.join(format!("{base}.json"));
        let out_path = dir.join(format!("{base}.sig.json"));
        std::fs::write(&in_path, b"original bytes").unwrap();
        let args = vec![
            "--seed".to_string(), TEST_SEED.to_string(),
            "--key-id".to_string(), "7".to_string(),
            "--in".to_string(), in_path.to_string_lossy().into_owned(),
            "--out".to_string(), out_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(cmd_sign(&args), ExitCode::SUCCESS);
        let pub_hex = hex_of(&test_pub());
        // Tampered input fails.
        std::fs::write(&in_path, b"tampered bytes").unwrap();
        let args = vec![
            "--pub".to_string(), pub_hex.clone(),
            "--in".to_string(), in_path.to_string_lossy().into_owned(),
            "--sidecar".to_string(), out_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(cmd_verify(&args), ExitCode::from(2));
        // Wrong key fails (restore bytes first).
        std::fs::write(&in_path, b"original bytes").unwrap();
        let other_seed = "1f".repeat(32);
        let args = vec![
            "--pub".to_string(), {
                let s = hex_to_32(&other_seed).unwrap();
                hex_of(
                    Ed25519KeyPair::from_seed_unchecked(&s)
                        .unwrap()
                        .public_key()
                        .as_ref(),
                )
            },
            "--in".to_string(), in_path.to_string_lossy().into_owned(),
            "--sidecar".to_string(), out_path.to_string_lossy().into_owned(),
        ];
        assert_eq!(cmd_verify(&args), ExitCode::from(2));
        std::fs::remove_file(&in_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    #[test]
    fn ceremony_fail_closed_codes() {
        // Usage errors exit 1; bad crypto exits 2; never success.
        let args = vec!["--seed".to_string(), "zz".to_string()];
        assert_eq!(cmd_sign(&args), ExitCode::from(1));
        let args = vec![
            "--pub".to_string(), "zz".to_string(),
            "--in".to_string(), "x".to_string(),
            "--sidecar".to_string(), "y".to_string(),
        ];
        assert_eq!(cmd_verify(&args), ExitCode::from(1));
    }
}
