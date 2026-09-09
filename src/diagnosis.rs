//! Bottom-up (L2 -> L3 -> L4) packet diagnosis.
//!
//! [`diagnose`] decodes a raw Ethernet frame and inspects each layer in turn,
//! stopping and reporting the first failure it can attribute to a layer. This
//! mirrors how a human troubleshoots "from the wire upward": you can't reason
//! about a TCP reset until you know the IP header even parsed and the
//! checksum was valid.

use etherparse::{
    Icmpv4Type, IpNumber, NetHeaders, PacketHeaders, TransportHeader,
    icmpv4::DestUnreachableHeader,
};
use x509_parser::prelude::{FromDer, X509Certificate};

/// UDP port used for the initial (non-NAT-traversal) IKE exchange.
const IKE_PORT: u16 = 500;
/// UDP port used for IKE once NAT-T encapsulation is negotiated.
const IKE_NAT_PORT: u16 = 4500;
/// Fixed-size IKEv2 header (RFC 7296 section 3.1): two 8-byte SPIs plus
/// next-payload/version/exchange-type/flags/message-id/length fields.
const IKE_HEADER_LEN: usize = 28;
/// IKEv2 payload type identifying a Certificate payload (RFC 7296 section 3.6).
const IKE_CERT_PAYLOAD_TYPE: u8 = 37;

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
    /// An IPsec ESP packet (its payload is encrypted, so only the SPI/sequence
    /// number, which are transmitted in the clear, can be reported).
    Layer3EspTraffic { spi: u32, sequence: u32 },
    /// An ESP packet was too short to contain a valid SPI/sequence number.
    Layer3EspMalformed,
    /// The TCP or UDP checksum does not match the segment contents.
    Layer4ChecksumInvalid,
    /// The TCP RST flag was set: the remote end refused/reset the connection.
    Layer4ConnectionReset,
    /// An ICMP "destination unreachable" message was received.
    Layer4DestinationUnreachable { icmp_code: u8 },
    /// An IKEv2 handshake message was recognized on the IKE/NAT-T ports.
    Layer4IkeHandshake {
        exchange_type: IkeExchangeType,
        initiator_spi: u64,
        responder_spi: u64,
    },
    /// An IKE packet was too short to contain a valid header.
    Layer4IkeMalformed,
    /// An IKE Certificate payload carried a parseable X.509 certificate; this
    /// is the PKI-backed peer identity used to authenticate the IKE_AUTH exchange.
    Layer4IkeCertificateIdentity { subject: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IkeExchangeType {
    SaInit,
    Auth,
    CreateChildSa,
    Informational,
    Unknown(u8),
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
            if ip_header.protocol == IpNumber::ENCAPSULATING_SECURITY_PAYLOAD {
                return diagnose_esp(headers.payload.slice());
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
                    if udp.source_port == IKE_PORT
                        || udp.destination_port == IKE_PORT
                        || udp.source_port == IKE_NAT_PORT
                        || udp.destination_port == IKE_NAT_PORT
                    {
                        return diagnose_ike(payload);
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

/// Extracts the SPI and sequence number from an ESP packet's clear-text
/// header (RFC 4303 section 2); the rest of the packet is encrypted and
/// cannot be inspected without the security association's keys.
fn diagnose_esp(payload: &[u8]) -> Diagnosis {
    if payload.len() < 8 {
        return Diagnosis::Layer3EspMalformed;
    }
    let spi = u32::from_be_bytes(payload[0..4].try_into().unwrap());
    let sequence = u32::from_be_bytes(payload[4..8].try_into().unwrap());
    Diagnosis::Layer3EspTraffic { spi, sequence }
}

/// Decodes an IKEv2 header and, if present, extracts the peer identity from
/// an unencrypted Certificate payload. Real deployments wrap payloads after
/// IKE_SA_INIT in an Encrypted (SK) payload, so this only recovers a
/// certificate that appears directly in the payload chain, which is
/// sufficient to demonstrate parsing an IKE Certificate payload and
/// resolving the PKI identity it carries.
fn diagnose_ike(payload: &[u8]) -> Diagnosis {
    if payload.len() < IKE_HEADER_LEN {
        return Diagnosis::Layer4IkeMalformed;
    }
    let initiator_spi = u64::from_be_bytes(payload[0..8].try_into().unwrap());
    let responder_spi = u64::from_be_bytes(payload[8..16].try_into().unwrap());
    let first_payload_type = payload[16];
    let exchange_type = ike_exchange_type(payload[18]);

    if let Some(cert_der) = find_ike_certificate(&payload[IKE_HEADER_LEN..], first_payload_type) {
        return match X509Certificate::from_der(cert_der) {
            Ok((_, cert)) => Diagnosis::Layer4IkeCertificateIdentity {
                subject: cert.subject().to_string(),
            },
            Err(_) => Diagnosis::Layer4IkeMalformed,
        };
    }

    Diagnosis::Layer4IkeHandshake {
        exchange_type,
        initiator_spi,
        responder_spi,
    }
}

fn ike_exchange_type(byte: u8) -> IkeExchangeType {
    match byte {
        34 => IkeExchangeType::SaInit,
        35 => IkeExchangeType::Auth,
        36 => IkeExchangeType::CreateChildSa,
        37 => IkeExchangeType::Informational,
        other => IkeExchangeType::Unknown(other),
    }
}

/// Walks the IKEv2 generic-payload chain (RFC 7296 section 3.2) looking for a
/// Certificate payload, and returns the raw certificate bytes (minus the
/// 1-byte certificate-encoding field) if one is found.
fn find_ike_certificate(mut payload: &[u8], mut current_type: u8) -> Option<&[u8]> {
    const NO_NEXT_PAYLOAD: u8 = 0;
    while current_type != NO_NEXT_PAYLOAD && payload.len() >= 4 {
        let next_type = payload[0];
        let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if length < 4 || length > payload.len() {
            break;
        }
        let body = &payload[4..length];
        if current_type == IKE_CERT_PAYLOAD_TYPE && !body.is_empty() {
            return Some(&body[1..]);
        }
        payload = &payload[length..];
        current_type = next_type;
    }
    None
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
