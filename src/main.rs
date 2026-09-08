use std::{env, fs, process};

use netstack_diagnostics::{diagnosis::diagnose, fixtures::sample_capture, pcap::PcapFile};

fn main() {
    let arguments: Vec<_> = env::args().skip(1).collect();
    let path = match arguments.as_slice() {
        [path] => path,
        [command, path] if command == "--generate-sample" => {
            fs::write(path, sample_capture()).unwrap_or_else(|e| {
                eprintln!("failed to write {path}: {e}");
                process::exit(1);
            });
            println!("wrote sample capture to {path}");
            return;
        }
        _ => {
            eprintln!("usage: netstack-diagnostics <path-to-pcap-file>");
            eprintln!("       netstack-diagnostics --generate-sample <output.pcap>");
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
