//! Bottom-up (L2 -> L3 -> L4) packet diagnosis.
//!
//! [`diagnose`] decodes a raw Ethernet frame and inspects each layer in turn,
//! stopping and reporting the first failure it can attribute to a layer. This
//! mirrors how a human troubleshoots "from the wire upward": you can't reason
//! about a TCP reset until you know the IP header even parsed and the
//! checksum was valid.

use etherparse::{Icmpv4Type, NetHeaders, PacketHeaders, TransportHeader, icmpv4::DestUnreachableHeader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diagnosis {
    /// Every layer decoded cleanly and no anomaly was found.
    Healthy,
    /// The Ethernet frame itself could not be parsed.
    Layer2Malformed(String),
    /// The frame parsed, but the EtherType isn't one we understand (not IP/ARP).
    Layer2UnknownEtherType(u16),
    /// The IPv4 header checksum does not match the header contents.
    Layer3ChecksumInvalid,
    /// The IPv4 TTL reached zero: this packet should have been dropped en route.
    Layer3TtlExpired,
    /// An ICMP "time exceeded" message was received (a router dropped the
    /// original packet because its TTL hit zero in transit).
    Layer3TimeExceededEnRoute,
    /// The TCP or UDP checksum does not match the segment contents.
    Layer4ChecksumInvalid,
    /// The TCP RST flag was set: the remote end refused/reset the connection.
    Layer4ConnectionReset,
    /// An ICMP "destination unreachable" message was received.
    Layer4DestinationUnreachable { icmp_code: u8 },
}

pub fn diagnose(frame: &[u8]) -> Diagnosis {
    let headers = match PacketHeaders::from_ethernet_slice(frame) {
        Ok(h) => h,
        Err(e) => return Diagnosis::Layer2Malformed(e.to_string()),
    };

    let net = match &headers.net {
        Some(n) => n,
        None => {
            let ether_type = headers
                .link
                .clone()
                .and_then(|l| l.ethernet2())
                .map(|e| e.ether_type.0)
                .unwrap_or(0);
            return Diagnosis::Layer2UnknownEtherType(ether_type);
        }
    };

    match net {
        NetHeaders::Ipv4(ip_header, _extensions) => {
            if ip_header.header_checksum != ip_header.calc_header_checksum() {
                return Diagnosis::Layer3ChecksumInvalid;
            }
            if ip_header.time_to_live == 0 {
                return Diagnosis::Layer3TtlExpired;
            }

            match &headers.transport {
                Some(TransportHeader::Tcp(tcp)) => {
                    let payload = headers.payload.slice();
                    if let Ok(expected) = tcp.calc_checksum_ipv4(ip_header, payload) {
                        if expected != tcp.checksum {
                            return Diagnosis::Layer4ChecksumInvalid;
                        }
                    }
                    if tcp.rst {
                        return Diagnosis::Layer4ConnectionReset;
                    }
                    Diagnosis::Healthy
                }
                Some(TransportHeader::Udp(udp)) => {
                    let payload = headers.payload.slice();
                    if udp.checksum != 0 {
                        if let Ok(expected) = udp.calc_checksum_ipv4(ip_header, payload) {
                            if expected != udp.checksum {
                                return Diagnosis::Layer4ChecksumInvalid;
                            }
                        }
                    }
                    Diagnosis::Healthy
                }
                Some(TransportHeader::Icmpv4(icmp)) => match &icmp.icmp_type {
                    Icmpv4Type::DestinationUnreachable(code) => {
                        Diagnosis::Layer4DestinationUnreachable {
                            icmp_code: dest_unreachable_code(code),
                        }
                    }
                    Icmpv4Type::TimeExceeded(_) => Diagnosis::Layer3TimeExceededEnRoute,
                    _ => Diagnosis::Healthy,
                },
                _ => Diagnosis::Healthy,
            }
        }
        _ => Diagnosis::Healthy,
    }
}

fn dest_unreachable_code(code: &DestUnreachableHeader) -> u8 {
    // DestUnreachableHeader doesn't expose a public code accessor for &self in
    // all versions, so re-derive it defensively instead of assuming one.
    match code {
        DestUnreachableHeader::Network => 0,
        DestUnreachableHeader::Host => 1,
        DestUnreachableHeader::Protocol => 2,
        DestUnreachableHeader::Port => 3,
        DestUnreachableHeader::FragmentationNeeded { .. } => 4,
        DestUnreachableHeader::SourceRouteFailed => 5,
        DestUnreachableHeader::NetworkUnknown => 6,
        DestUnreachableHeader::HostUnknown => 7,
        DestUnreachableHeader::Isolated => 8,
        DestUnreachableHeader::NetworkProhibited => 9,
        DestUnreachableHeader::HostProhibited => 10,
        DestUnreachableHeader::TosNetwork => 11,
        DestUnreachableHeader::TosHost => 12,
        DestUnreachableHeader::FilterProhibited => 13,
        DestUnreachableHeader::HostPrecedenceViolation => 14,
        DestUnreachableHeader::PrecedenceCutoff => 15,
    }
}
