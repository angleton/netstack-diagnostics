//! One-off generator for the static X.509 DER embedded in fixtures.rs.
//! Run with `cargo run --example gen_ike_cert`, paste the output, then discard this file.
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

fn main() {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "vpn-gateway.example.com");
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let der = cert.der();

    print!("pub const SAMPLE_IKE_CERT_DER: &[u8] = &[");
    for (i, byte) in der.iter().enumerate() {
        if i % 12 == 0 {
            print!("\n    ");
        }
        print!("0x{byte:02x}, ");
    }
    println!("\n];");
}
