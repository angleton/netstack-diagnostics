use cucumber::{World, given, then, when};
use netstack_diagnostics::diagnosis::{Diagnosis, diagnose};
use netstack_diagnostics::fixtures;
use netstack_diagnostics::pcap::{PcapFile, write_pcap_file};

#[derive(Debug, Default, World)]
struct DiagnosisWorld {
    capture: Vec<u8>,
    diagnosis: Option<Diagnosis>,
}

#[given(expr = "a packet capture containing a {string} packet")]
async fn given_capture(world: &mut DiagnosisWorld, name: String) {
    let packet = fixtures::by_name(&name).unwrap_or_else(|| panic!("unknown fixture: {name}"));
    world.capture = write_pcap_file(&[(0, 0, &packet)]);
}

#[when("the capture is analyzed")]
async fn when_analyzed(world: &mut DiagnosisWorld) {
    let pcap = PcapFile::parse(&world.capture).expect("capture should be a valid pcap file");
    let record = pcap
        .records()
        .next()
        .expect("capture should contain one record")
        .expect("record should be well-formed");
    world.diagnosis = Some(diagnose(record.data));
}

#[then(expr = "the diagnosis is {string}")]
async fn then_diagnosis(world: &mut DiagnosisWorld, expected: String) {
    let actual = world
        .diagnosis
        .as_ref()
        .expect("diagnosis should have been computed");
    let actual_name = format!("{actual:?}");
    let actual_name = actual_name
        .split(['{', '('])
        .next()
        .unwrap()
        .trim();
    assert_eq!(actual_name, expected);
}

#[then(expr = "the icmp code is {int}")]
async fn then_icmp_code(world: &mut DiagnosisWorld, expected: u8) {
    match world.diagnosis.as_ref() {
        Some(Diagnosis::Layer4DestinationUnreachable { icmp_code }) => {
            assert_eq!(*icmp_code, expected);
        }
        other => panic!("expected Layer4DestinationUnreachable, got {other:?}"),
    }
}

#[then(expr = "the ether type is {int}")]
async fn then_ether_type(world: &mut DiagnosisWorld, expected: u16) {
    match world.diagnosis.as_ref() {
        Some(Diagnosis::Layer2UnknownEtherType(ether_type)) => {
            assert_eq!(*ether_type, expected);
        }
        other => panic!("expected Layer2UnknownEtherType, got {other:?}"),
    }
}

#[then(expr = "the diagnosis message contains {string}")]
async fn then_diagnosis_message_contains(world: &mut DiagnosisWorld, expected: String) {
    match world.diagnosis.as_ref() {
        Some(Diagnosis::Layer2Malformed(message)) => {
            assert!(
                message.contains(&expected),
                "expected message to contain {expected:?}, got {message:?}"
            );
        }
        other => panic!("expected Layer2Malformed, got {other:?}"),
    }
}

#[then(expr = "the spi is {int}")]
async fn then_spi(world: &mut DiagnosisWorld, expected: u32) {
    match world.diagnosis.as_ref() {
        Some(Diagnosis::Layer3EspTraffic { spi, .. }) => assert_eq!(*spi, expected),
        other => panic!("expected Layer3EspTraffic, got {other:?}"),
    }
}

#[then(expr = "the certificate subject contains {string}")]
async fn then_certificate_subject_contains(world: &mut DiagnosisWorld, expected: String) {
    match world.diagnosis.as_ref() {
        Some(Diagnosis::Layer4IkeCertificateIdentity { subject }) => {
            assert!(
                subject.contains(&expected),
                "expected subject to contain {expected:?}, got {subject:?}"
            );
        }
        other => panic!("expected Layer4IkeCertificateIdentity, got {other:?}"),
    }
}

fn main() {
    futures::executor::block_on(DiagnosisWorld::run("tests/features"));
}
