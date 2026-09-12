# Netstack Diagnostics

A Rust project demonstrating command of the networking stack from Layer 2
(Ethernet) through Layer 4 (TCP/UDP/ICMP): decoding raw frames, reasoning
about failures "from the wire upward", and reading packet captures without
relying on a GUI tool or libpcap.

## What's here

- `src/pcap.rs` — a hand-written reader/writer for the classic libpcap
  capture file format (global header + record headers). No libpcap/npcap
  dependency; pure byte parsing.
- `src/diagnosis.rs` — decodes an Ethernet frame with
  [`etherparse`](https://docs.rs/etherparse) and walks the layers bottom-up
  (L2 → L3 → L4), attributing the first anomaly found to the correct layer:
  malformed frames, unknown EtherTypes, bad IPv4 checksums, expired TTLs,
  bad TCP/UDP checksums, TCP resets, and ICMP destination-unreachable /
  time-exceeded messages.
- `src/fixtures.rs` — synthetic packet fixtures (healthy and deliberately
  broken) used by tests, so no real captures are needed.
- `tests/features/diagnosis.feature` + `tests/cucumber.rs` — BDD scenarios
  (via [`cucumber`](https://docs.rs/cucumber)) exercising the diagnosis
  engine end-to-end through a synthetic pcap file.

## Usage

```powershell
cargo run -- path\to\capture.pcap
```

Prints a per-packet diagnosis for every record in a classic (libpcap format)
capture file.

Generate a deterministic sample capture containing one packet for every
scenario in `tests/features/diagnosis.feature`, then analyze it:

```powershell
cargo run -- --generate-sample pcaps/master.pcap
cargo run -- pcaps/master.pcap
```

The records are written in the same order as the scenarios in the feature
file, including the deliberately malformed, unknown EtherType, ESP, and IKE
examples.

## Tests

```powershell
cargo test
```

Runs unit tests plus the Cucumber BDD suite.

