//! Minimal, dependency-free reader/writer for the classic (libpcap) capture
//! file format: a 24-byte global header followed by `(16-byte record header,
//! packet bytes)` pairs. This intentionally avoids any pcap-parsing crate so
//! that container framing is decoded "by hand", same as the protocol layers.

pub const PCAP_MAGIC_MICROS: u32 = 0xa1b2_c3d4;
pub const LINKTYPE_ETHERNET: u32 = 1;

const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum PcapError {
    TooShort,
    BadMagic(u32),
    UnsupportedLinkType(u32),
    TruncatedRecord,
}

#[derive(Debug)]
pub struct PcapRecord<'a> {
    pub timestamp_secs: u32,
    pub timestamp_micros: u32,
    pub data: &'a [u8],
}

pub struct PcapFile<'a> {
    data: &'a [u8],
}

impl<'a> PcapFile<'a> {
    /// Parses (and validates) the global header of a pcap byte buffer.
    pub fn parse(data: &'a [u8]) -> Result<Self, PcapError> {
        if data.len() < GLOBAL_HEADER_LEN {
            return Err(PcapError::TooShort);
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != PCAP_MAGIC_MICROS {
            return Err(PcapError::BadMagic(magic));
        }
        let network = u32::from_le_bytes(data[20..24].try_into().unwrap());
        if network != LINKTYPE_ETHERNET {
            return Err(PcapError::UnsupportedLinkType(network));
        }
        Ok(PcapFile { data })
    }

    pub fn records(&self) -> PcapRecordIter<'a> {
        PcapRecordIter {
            data: &self.data[GLOBAL_HEADER_LEN..],
        }
    }
}

pub struct PcapRecordIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for PcapRecordIter<'a> {
    type Item = Result<PcapRecord<'a>, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < RECORD_HEADER_LEN {
            self.data = &[];
            return Some(Err(PcapError::TruncatedRecord));
        }
        let ts_sec = u32::from_le_bytes(self.data[0..4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(self.data[4..8].try_into().unwrap());
        let incl_len = u32::from_le_bytes(self.data[8..12].try_into().unwrap()) as usize;
        let rest = &self.data[RECORD_HEADER_LEN..];
        if rest.len() < incl_len {
            self.data = &[];
            return Some(Err(PcapError::TruncatedRecord));
        }
        let (record_data, remaining) = rest.split_at(incl_len);
        self.data = remaining;
        Some(Ok(PcapRecord {
            timestamp_secs: ts_sec,
            timestamp_micros: ts_usec,
            data: record_data,
        }))
    }
}

/// Builds a synthetic pcap file (Ethernet link type) from raw frame bytes.
pub fn write_pcap_file(packets: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PCAP_MAGIC_MICROS.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // version_major
    out.extend_from_slice(&4u16.to_le_bytes()); // version_minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    for (sec, usec, data) in packets {
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_single_packet() {
        let packet = [1u8, 2, 3, 4, 5];
        let bytes = write_pcap_file(&[(10, 20, &packet)]);
        let pcap = PcapFile::parse(&bytes).unwrap();
        let records: Vec<_> = pcap.records().collect();
        assert_eq!(records.len(), 1);
        let record = records[0].as_ref().unwrap();
        assert_eq!(record.timestamp_secs, 10);
        assert_eq!(record.timestamp_micros, 20);
        assert_eq!(record.data, &packet);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = write_pcap_file(&[(0, 0, &[])]);
        bytes[0] = 0;
        assert!(matches!(PcapFile::parse(&bytes), Err(PcapError::BadMagic(_))));
    }
}
