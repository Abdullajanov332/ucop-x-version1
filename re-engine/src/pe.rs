//! PE (Portable Executable) binary format parser.

/// Machine types for PE files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeMachine {
    I386,
    Amd64,
    Arm64,
    Unknown(u16),
}

/// PE header information.
#[derive(Debug, Clone)]
pub struct PeHeader {
    pub machine: PeMachine,
    pub num_sections: u16,
    pub timestamp: u32,
    pub entry_point: u64,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_code: u32,
    pub subsystem: u16,
}

/// Parse a PE header from raw bytes.
pub fn parse_header(data: &[u8]) -> Result<PeHeader, String> {
    if data.len() < 64 {
        return Err("data too short".into());
    }
    if data[0] != 0x4D || data[1] != 0x5A {
        return Err("not a valid DOS header".into());
    }

    // Get pointer to PE signature
    let pe_offset = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
    if pe_offset + 24 > data.len() {
        return Err("PE signature offset out of bounds".into());
    }

    // Check PE\0\0 signature
    if &data[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
        return Err("not a valid PE signature".into());
    }

    let coff = pe_offset + 4;
    let machine = match u16::from_le_bytes(data[coff..coff + 2].try_into().unwrap()) {
        0x14c => PeMachine::I386,
        0x8664 => PeMachine::Amd64,
        0xAA64 => PeMachine::Arm64,
        other => PeMachine::Unknown(other),
    };
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap());
    let timestamp = u32::from_le_bytes(data[coff + 4..coff + 8].try_into().unwrap());

    // Optional header follows COFF header
    let opt_header_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let opt_header_offset = coff + 20;

    if opt_header_offset + opt_header_size > data.len() {
        return Err("optional header out of bounds".into());
    }

    let magic = u16::from_le_bytes(data[opt_header_offset..opt_header_offset + 2].try_into().unwrap());
    let (entry_point, image_base, size_of_image, size_of_code, subsystem) = match magic {
        0x10b => {
            // PE32
            let ep = u32::from_le_bytes(
                data[opt_header_offset + 16..opt_header_offset + 20]
                    .try_into()
                    .unwrap(),
            );
            let ib = u32::from_le_bytes(
                data[opt_header_offset + 28..opt_header_offset + 32]
                    .try_into()
                    .unwrap(),
            );
            let soi = u32::from_le_bytes(
                data[opt_header_offset + 56..opt_header_offset + 60]
                    .try_into()
                    .unwrap(),
            );
            let soc = u32::from_le_bytes(
                data[opt_header_offset + 60..opt_header_offset + 64]
                    .try_into()
                    .unwrap(),
            );
            let ss = u16::from_le_bytes(
                data[opt_header_offset + 68..opt_header_offset + 70]
                    .try_into()
                    .unwrap(),
            );
            (ep as u64, ib as u64, soi, soc, ss)
        }
        0x20b => {
            // PE32+
            let ep = u32::from_le_bytes(
                data[opt_header_offset + 16..opt_header_offset + 20]
                    .try_into()
                    .unwrap(),
            );
            let ib = u64::from_le_bytes(
                data[opt_header_offset + 24..opt_header_offset + 32]
                    .try_into()
                    .unwrap(),
            );
            let soi = u32::from_le_bytes(
                data[opt_header_offset + 56..opt_header_offset + 60]
                    .try_into()
                    .unwrap(),
            );
            let soc = u32::from_le_bytes(
                data[opt_header_offset + 60..opt_header_offset + 64]
                    .try_into()
                    .unwrap(),
            );
            let ss = u16::from_le_bytes(
                data[opt_header_offset + 70..opt_header_offset + 72]
                    .try_into()
                    .unwrap(),
            );
            (ep, ib, soi, soc, ss)
        }
        _ => return Err("unknown optional header magic".into()),
    };

    Ok(PeHeader {
        machine,
        num_sections,
        timestamp,
        entry_point,
        image_base,
        size_of_image,
        size_of_code,
        subsystem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_pe() {
        assert!(parse_header(&[0; 64]).is_err());
    }
}
