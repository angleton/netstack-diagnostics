use std::{env, fs, process};

use netstack_diagnostics::{diagnosis::diagnose, pcap::PcapFile};

fn main() {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: netstack-diagnostics <path-to-pcap-file>");
            process::exit(2);
        }
    };

    let bytes = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        process::exit(1);
    });

    let pcap = PcapFile::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("failed to parse {path} as a pcap file: {e:?}");
        process::exit(1);
    });

    for (index, record) in pcap.records().enumerate() {
        match record {
            Ok(record) => {
                let diagnosis = diagnose(record.data);
                println!("packet #{index}: {diagnosis:?}");
            }
            Err(e) => println!("packet #{index}: capture error: {e:?}"),
        }
    }
}
