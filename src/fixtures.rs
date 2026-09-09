//! Synthetic packet fixtures used by unit tests and BDD scenarios.
//!
//! Each fixture builds a raw Ethernet frame byte-by-byte (Ethernet header,
//! then IPv4 header, then a transport header/payload) so that both the
//! "healthy" and "broken" variants are fully under our control.

use etherparse::{
    EtherType, Ethernet2Header, Icmpv4Header, Icmpv4Type, IpNumber, Ipv4Header, TcpHeader,
    UdpHeader,
    icmpv4::{DestUnreachableHeader, TimeExceededCode},
};

use crate::pcap::write_pcap_file;

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SRC_IP: [u8; 4] = [10, 0, 0, 1];
const DST_IP: [u8; 4] = [10, 0, 0, 2];

fn ethernet_header() -> Ethernet2Header {
    Ethernet2Header {
        source: SRC_MAC,
        destination: DST_MAC,
        ether_type: EtherType::IPV4,
    }
}

fn frame(ip: &Ipv4Header, transport_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ethernet_header().to_bytes());
    out.extend_from_slice(&ip.to_bytes());
    out.extend_from_slice(transport_bytes);
    out
}

fn tcp_ip_frame(rst: bool, corrupt_ip_checksum: bool, ttl: u8) -> Vec<u8> {
    let payload = b"hello";
    let mut tcp = TcpHeader::new(51000, 80, 1000, 64240);
    tcp.ack = !rst;
    tcp.rst = rst;

    let mut ip = Ipv4Header::new(
        (tcp.header_len() + payload.len()) as u16,
        ttl,
        IpNumber::TCP,
        SRC_IP,
        DST_IP,
    )
    .unwrap();
    ip.header_checksum = ip.calc_header_checksum();
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload).unwrap();

    if corrupt_ip_checksum {
        ip.header_checksum ^= 0xFFFF;
    }

    let mut transport = tcp.to_bytes().to_vec();
    transport.extend_from_slice(payload);
    frame(&ip, &transport)
}

pub fn healthy_tcp() -> Vec<u8> {
    tcp_ip_frame(false, false, 64)
}

pub fn bad_ip_checksum() -> Vec<u8> {
    tcp_ip_frame(false, true, 64)
}

pub fn ttl_expired() -> Vec<u8> {
    tcp_ip_frame(false, false, 0)
}

pub fn tcp_reset() -> Vec<u8> {
    tcp_ip_frame(true, false, 64)
}

fn udp_ip_frame(corrupt_checksum: bool) -> Vec<u8> {
    let payload = b"datagram";
    let mut ip = Ipv4Header::new(
        (UdpHeader::LEN + payload.len()) as u16,
        64,
        IpNumber::UDP,
        SRC_IP,
        DST_IP,
    )
    .unwrap();
    ip.header_checksum = ip.calc_header_checksum();

    let mut udp = UdpHeader::with_ipv4_checksum(53000, 53, &ip, payload).unwrap();
    if corrupt_checksum {
        udp.checksum ^= 0xFFFF;
    }

    let mut transport = udp.to_bytes().to_vec();
    transport.extend_from_slice(payload);
    frame(&ip, &transport)
}

pub fn healthy_udp() -> Vec<u8> {
    udp_ip_frame(false)
}

pub fn bad_udp_checksum() -> Vec<u8> {
    udp_ip_frame(true)
}

fn icmp_frame(icmp_type: Icmpv4Type) -> Vec<u8> {
    // Payload: a stand-in for "internet header + 64 bits of original datagram".
    let payload = [0u8; 28];
    let mut icmp = Icmpv4Header::new(icmp_type);
    icmp.checksum = icmp.icmp_type.calc_checksum(&payload);

    let mut transport = icmp.to_bytes().to_vec();
    transport.extend_from_slice(&payload);

    let ip = {
        let mut ip = Ipv4Header::new(
            transport.len() as u16,
            64,
            IpNumber::ICMP,
            SRC_IP,
            DST_IP,
        )
        .unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        ip
    };
    frame(&ip, &transport)
}

pub fn icmp_port_unreachable() -> Vec<u8> {
    icmp_frame(Icmpv4Type::DestinationUnreachable(DestUnreachableHeader::Port))
}

pub fn icmp_time_exceeded() -> Vec<u8> {
    icmp_frame(Icmpv4Type::TimeExceeded(TimeExceededCode::TtlExceededInTransit))
}

pub fn truncated_frame() -> Vec<u8> {
    // Only 6 bytes: not even a full Ethernet header (14 bytes minimum).
    vec![0xAA; 6]
}

pub fn unknown_ether_type() -> Vec<u8> {
    let header = Ethernet2Header {
        source: SRC_MAC,
        destination: DST_MAC,
        // Not IPv4/IPv6/ARP, so etherparse leaves `net` as None.
        ether_type: EtherType::WAKE_ON_LAN,
    };
    let mut out = header.to_bytes().to_vec();
    out.extend_from_slice(&[0u8; 28]);
    out
}

/// A self-signed X.509 (CN=vpn-gateway.example.com) certificate in DER form,
/// generated once with `rcgen` (see examples/gen_ike_cert.rs) and embedded
/// here so this fixture doesn't need a certificate-generation dependency at
/// runtime.
const SAMPLE_IKE_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x45, 0x30, 0x81, 0xec, 0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x14, 0x11, 0x97, 0x0b, 0x0c, 0x9a, 0x8e, 0x24, 0x33, 0x44, 0x09,
    0x26, 0x61, 0xe8, 0x03, 0xde, 0x60, 0x11, 0x56, 0x4c, 0xe9, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x22,
    0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x76,
    0x70, 0x6e, 0x2d, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x65,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x20,
    0x17, 0x0d, 0x37, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5a, 0x18, 0x0f, 0x34, 0x30, 0x39, 0x36, 0x30, 0x31, 0x30,
    0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x22, 0x31, 0x20,
    0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x17, 0x76, 0x70, 0x6e,
    0x2d, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x8b,
    0x62, 0x6c, 0x98, 0xd0, 0xd1, 0xca, 0x15, 0xd5, 0xae, 0x33, 0xe0, 0x6c,
    0xb6, 0x85, 0x2e, 0xfb, 0x59, 0x82, 0xb3, 0xa2, 0xab, 0xe4, 0xc6, 0xa6,
    0xcd, 0xc0, 0xf4, 0xe9, 0x92, 0x1d, 0x1c, 0xe0, 0x72, 0x2c, 0xce, 0x2c,
    0x71, 0xe6, 0x2f, 0xda, 0x24, 0xe8, 0x34, 0x92, 0x65, 0xca, 0x75, 0x1c,
    0x3a, 0x8b, 0x3b, 0xed, 0xcc, 0x20, 0x6f, 0xdd, 0x6e, 0xd2, 0x97, 0x55,
    0x3d, 0x2e, 0xdc, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x5a, 0x2b,
    0xcb, 0xd1, 0x90, 0xcd, 0x86, 0x0c, 0xee, 0x61, 0x25, 0x51, 0xb7, 0xa5,
    0x32, 0x1a, 0x2d, 0x18, 0xa9, 0x61, 0xc9, 0xeb, 0x48, 0x88, 0x5e, 0xa2,
    0xab, 0xd5, 0x95, 0x87, 0xb1, 0x72, 0x02, 0x21, 0x00, 0xdd, 0x15, 0x29,
    0x61, 0x1e, 0x4f, 0x89, 0x7d, 0xe2, 0x4f, 0x5d, 0x8f, 0x7a, 0x50, 0x5b,
    0x7c, 0x80, 0xf5, 0xf8, 0xd6, 0xa4, 0x2b, 0xdf, 0xc6, 0x99, 0x0c, 0x7c,
    0x45, 0x44, 0xe4, 0xff, 0xb6,
];

pub fn esp_traffic() -> Vec<u8> {
    let spi: u32 = 0x1234_5678;
    let sequence: u32 = 1;
    let mut esp_payload = Vec::new();
    esp_payload.extend_from_slice(&spi.to_be_bytes());
    esp_payload.extend_from_slice(&sequence.to_be_bytes());
    esp_payload.extend_from_slice(&[0u8; 16]); // stand-in for encrypted data

    let mut ip = Ipv4Header::new(
        esp_payload.len() as u16,
        64,
        IpNumber::ENCAPSULATING_SECURITY_PAYLOAD,
        SRC_IP,
        DST_IP,
    )
    .unwrap();
    ip.header_checksum = ip.calc_header_checksum();
    frame(&ip, &esp_payload)
}

fn ike_header(exchange_type: u8, first_payload_type: u8, message_len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(IKE_HEADER_LEN);
    header.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes()); // initiator SPI
    header.extend_from_slice(&0u64.to_be_bytes()); // responder SPI: unset before IKE_SA_INIT reply
    header.push(first_payload_type);
    header.push(0x20); // version 2.0
    header.push(exchange_type);
    header.push(0x08); // flags: initiator
    header.extend_from_slice(&0u32.to_be_bytes()); // message id
    header.extend_from_slice(&(message_len as u32).to_be_bytes());
    header
}

const IKE_HEADER_LEN: usize = 28;
const IKE_EXCHANGE_SA_INIT: u8 = 34;
const IKE_EXCHANGE_AUTH: u8 = 35;
const IKE_PAYLOAD_SA: u8 = 33;
const IKE_PAYLOAD_CERT: u8 = 37;
const IKE_PAYLOAD_NONE: u8 = 0;

fn ike_udp_frame(ike_message: &[u8]) -> Vec<u8> {
    let mut ip = Ipv4Header::new(
        (UdpHeader::LEN + ike_message.len()) as u16,
        64,
        IpNumber::UDP,
        SRC_IP,
        DST_IP,
    )
    .unwrap();
    ip.header_checksum = ip.calc_header_checksum();

    let udp = UdpHeader::with_ipv4_checksum(4500, 500, &ip, ike_message).unwrap();
    let mut transport = udp.to_bytes().to_vec();
    transport.extend_from_slice(ike_message);
    frame(&ip, &transport)
}

pub fn ike_sa_init() -> Vec<u8> {
    let message = ike_header(IKE_EXCHANGE_SA_INIT, IKE_PAYLOAD_SA, IKE_HEADER_LEN);
    ike_udp_frame(&message)
}

pub fn ike_auth_with_certificate() -> Vec<u8> {
    // One Certificate payload: generic payload header (next=0, reserved,
    // 2-byte length) + 1-byte cert encoding (4 = X.509 Certificate - Signature)
    // + the DER-encoded certificate itself.
    let cert_payload_len = 4 + 1 + SAMPLE_IKE_CERT_DER.len();
    let mut message = ike_header(
        IKE_EXCHANGE_AUTH,
        IKE_PAYLOAD_CERT,
        IKE_HEADER_LEN + cert_payload_len,
    );
    message.push(IKE_PAYLOAD_NONE);
    message.push(0); // critical/reserved
    message.extend_from_slice(&(cert_payload_len as u16).to_be_bytes());
    message.push(4); // cert encoding: X.509 Certificate - Signature
    message.extend_from_slice(SAMPLE_IKE_CERT_DER);
    ike_udp_frame(&message)
}

/// Builds a deterministic classic pcap containing every diagnostic scenario.
pub fn sample_capture() -> Vec<u8> {
    let packets = [
        healthy_tcp(),
        bad_ip_checksum(),
        ttl_expired(),
        tcp_reset(),
        healthy_udp(),
        bad_udp_checksum(),
        icmp_port_unreachable(),
        icmp_time_exceeded(),
        truncated_frame(),
    ];
    let records: Vec<_> = packets
        .iter()
        .enumerate()
        .map(|(index, packet)| (index as u32, 0, packet.as_slice()))
        .collect();
    write_pcap_file(&records)
}

/// Looks up a named fixture, for use from feature-file step definitions.
pub fn by_name(name: &str) -> Option<Vec<u8>> {
    match name {
        "healthy_tcp" => Some(healthy_tcp()),
        "bad_ip_checksum" => Some(bad_ip_checksum()),
        "ttl_expired" => Some(ttl_expired()),
        "tcp_reset" => Some(tcp_reset()),
        "healthy_udp" => Some(healthy_udp()),
        "bad_udp_checksum" => Some(bad_udp_checksum()),
        "icmp_port_unreachable" => Some(icmp_port_unreachable()),
        "icmp_time_exceeded" => Some(icmp_time_exceeded()),
        "truncated_frame" => Some(truncated_frame()),
        "unknown_ether_type" => Some(unknown_ether_type()),
        "esp_traffic" => Some(esp_traffic()),
        "ike_sa_init" => Some(ike_sa_init()),
        "ike_auth_with_certificate" => Some(ike_auth_with_certificate()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        diagnosis::{Diagnosis, diagnose},
        pcap::PcapFile,
    };

    use super::sample_capture;

    #[test]
    fn sample_capture_exercises_every_diagnosis_scenario() {
        let capture = sample_capture();
        let diagnoses: Vec<_> = PcapFile::parse(&capture)
            .unwrap()
            .records()
            .map(|record| diagnose(record.unwrap().data))
            .collect();

        assert!(matches!(diagnoses[0], Diagnosis::Healthy));
        assert!(matches!(diagnoses[1], Diagnosis::Layer3ChecksumInvalid));
        assert!(matches!(diagnoses[2], Diagnosis::Layer3TtlExpired));
        assert!(matches!(diagnoses[3], Diagnosis::Layer4ConnectionReset));
        assert!(matches!(diagnoses[4], Diagnosis::Healthy));
        assert!(matches!(diagnoses[5], Diagnosis::Layer4ChecksumInvalid));
        assert!(matches!(
            diagnoses[6],
            Diagnosis::Layer4DestinationUnreachable { icmp_code: 3 }
        ));
        assert!(matches!(diagnoses[7], Diagnosis::Layer3TimeExceededEnRoute));
        assert!(matches!(diagnoses[8], Diagnosis::Layer2Malformed(_)));
    }
}
