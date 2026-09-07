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
        _ => None,
    }
}
