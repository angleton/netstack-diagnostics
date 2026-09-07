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

fn main() {
    futures::executor::block_on(DiagnosisWorld::run("tests/features"));
}
