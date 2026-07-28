//! Mach-O binary format parser.

/// Mach-O CPU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoCpuType {
    X86,
    X86_64,
    Arm,
    Arm64,
    Unknown(u32),
}

/// Mach-O header information.
#[derive(Debug, Clone)]
pub struct MachOHeader {
    pub cpu_type: MachoCpuType,
    pub file_type: u32,
    pub num_commands: u32,
    pub flags: u32,
}

/// Parse a Mach-O header from raw bytes.
pub fn parse_header(data: &[u8]) -> Result<MachOHeader, String> {
    if data.len() < 28 {
        return Err("data too short for Mach-O header".into());
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let is_64 = match magic {
        0xFEEDFACE | 0xCEFAEDFE => false,
        0xFEEDFACF | 0xCFFAEDFE => true,
        _ => return Err("not a valid Mach-O magic".into()),
    };

    let header_size: usize = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return Err("data too short for Mach-O header with arch".into());
    }

    let cpu_type_val = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let cpu_type = match cpu_type_val {
        7 => MachoCpuType::X86,
        0x0100_0007 => MachoCpuType::X86_64,
        12 => MachoCpuType::Arm,
        0x0100_000c => MachoCpuType::Arm64,
        other => MachoCpuType::Unknown(other),
    };
    let file_type = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let num_commands = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let flags = u32::from_le_bytes(data[24..28].try_into().unwrap());

    Ok(MachOHeader {
        cpu_type,
        file_type,
        num_commands,
        flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_macho() {
        assert!(parse_header(&[0; 28]).is_err());
    }
}
