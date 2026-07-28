//! ELF binary format parser.

/// Represents an ELF header.
#[derive(Debug, Clone)]
pub struct ElfHeader {
    pub class: ElfClass,
    pub endian: ElfEndian,
    pub arch: u16,
    pub entry_point: u64,
    pub section_offset: u64,
    pub num_sections: u16,
    pub program_offset: u64,
    pub num_segments: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfEndian {
    Little,
    Big,
}

/// Parse an ELF header from raw bytes.
pub fn parse_header(data: &[u8]) -> Result<ElfHeader, String> {
    if data.len() < 64 {
        return Err("data too short for ELF header".into());
    }
    if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err("not a valid ELF magic".into());
    }

    let class = match data[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return Err("unknown ELF class".into()),
    };
    let endian = match data[5] {
        1 => ElfEndian::Little,
        2 => ElfEndian::Big,
        _ => return Err("unknown ELF endianness".into()),
    };

    let (entry_offset, phoff_offset, shoff_offset) = match class {
        ElfClass::Elf32 => (24, 28, 32),
        ElfClass::Elf64 => (24, 32, 40),
    };

    let read_u64 = |offset: usize| -> u64 {
        if endian == ElfEndian::Little {
            u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
        } else {
            u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
        }
    };

    let entry_point = read_u64(entry_offset);
    let section_offset = read_u64(shoff_offset);
    let program_offset = read_u64(phoff_offset);

    let num_sections = u16::from_ne_bytes([data[60], data[61]]);
    let num_segments = u16::from_ne_bytes([data[56], data[57]]);

    Ok(ElfHeader {
        class,
        endian,
        arch: u16::from_ne_bytes([data[18], data[19]]),
        entry_point,
        section_offset,
        num_sections,
        program_offset,
        num_segments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_header() {
        assert!(parse_header(&[0; 10]).is_err());
        assert!(parse_header(&[0x7F, 0, 0, 0, 0; 16]).is_err());
    }
}
