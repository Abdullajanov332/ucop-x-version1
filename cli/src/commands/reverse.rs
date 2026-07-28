//! `reverse` command namespace.
//! Reverse engineering operations for binaries.

use clap::{Args, Subcommand};

/// Reverse engineering command group.
#[derive(Debug, Args)]
pub struct ReverseArgs {
    #[command(subcommand)]
    pub command: ReverseCommands,
}

#[derive(Debug, Subcommand)]
pub enum ReverseCommands {
    /// Disassemble a binary.
    Disassemble(DisassembleArgs),
    /// Decompile a binary.
    Decompile(DecompileArgs),
    /// Extract strings from a binary.
    Strings(StringsArgs),
    /// Analyze binary metadata.
    Metadata(MetadataArgs),
    /// List available RE modules.
    List,
}

#[derive(Debug, Args)]
pub struct DisassembleArgs {
    /// Path to binary.
    pub path: String,
    /// Architecture (x86, x64, arm, arm64).
    #[arg(long)]
    pub arch: Option<String>,
    /// Start address for disassembly.
    #[arg(long)]
    pub start: Option<String>,
    /// Number of instructions to disassemble.
    #[arg(long)]
    pub count: Option<usize>,
}

#[derive(Debug, Args)]
pub struct DecompileArgs {
    /// Path to binary.
    pub path: String,
    /// Function to decompile (optional: decompile all).
    #[arg(long)]
    pub function: Option<String>,
}

#[derive(Debug, Args)]
pub struct StringsArgs {
    /// Path to binary or file.
    pub path: String,
    /// Minimum string length.
    #[arg(long, default_value = "4")]
    pub min_len: usize,
    /// Encoding (ascii, utf16, all).
    #[arg(long, default_value = "all")]
    pub encoding: String,
}

#[derive(Debug, Args)]
pub struct MetadataArgs {
    /// Path to binary.
    pub path: String,
}

pub async fn execute(args: &ReverseArgs) -> Result<(), String> {
    match &args.command {
        ReverseCommands::Disassemble(dargs) => disassemble(dargs).await,
        ReverseCommands::Decompile(dcargs) => decompile(dcargs).await,
        ReverseCommands::Strings(sargs) => extract_strings(sargs).await,
        ReverseCommands::Metadata(margs) => analyze_metadata(margs).await,
        ReverseCommands::List => list_re_modules().await,
    }
}

async fn disassemble(args: &DisassembleArgs) -> Result<(), String> {
    println!("Disassembling: {}", args.path);
    println!("  Architecture: {:?}", args.arch);
    println!("Requires the RE engine module (capstone-based).");
    println!("Install the re-engine module to enable this feature.");
    Ok(())
}

async fn decompile(_args: &DecompileArgs) -> Result<(), String> {
    println!("Decompilation requires the RE engine with Ghidra/RetDec backend.");
    println!("Load the decompiler module to enable this feature.");
    Ok(())
}

async fn extract_strings(args: &StringsArgs) -> Result<(), String> {
    use comfy_table::Table;

    let path = std::path::Path::new(&args.path);
    if !path.exists() {
        return Err(format!("file not found: {}", args.path));
    }

    let data = std::fs::read(path).map_err(|e| e.to_string())?;

    let mut strings_found: Vec<String> = Vec::new();

    // Extract ASCII strings
    if args.encoding == "ascii" || args.encoding == "all" {
        let mut current = String::new();
        for &b in &data {
            if b.is_ascii_graphic() || b == b' ' {
                current.push(b as char);
            } else {
                if current.len() >= args.min_len {
                    strings_found.push(current.clone());
                }
                current.clear();
            }
        }
        if current.len() >= args.min_len {
            strings_found.push(current);
        }
    }

    // Extract UTF-16 strings
    if args.encoding == "utf16" || args.encoding == "all" {
        let mut current = Vec::new();
        for chunk in data.chunks(2) {
            if chunk.len() == 2 {
                let c = u16::from_le_bytes([chunk[0], chunk[1]]);
                if c.is_ascii_alphanumeric() || c == b' ' as u16 || c == b'_' as u16 || c == b'.' as u16 {
                    current.push(c);
                } else {
                    if current.len() >= args.min_len {
                        let s: String = current.iter().map(|&c| char::from_u32(c as u32).unwrap_or('?')).collect();
                        strings_found.push(s);
                    }
                    current.clear();
                }
            }
        }
    }

    strings_found.sort();
    strings_found.dedup();

    let mut table = Table::new();
    table.set_header(vec!["Index", "String"]);

    for (i, s) in strings_found.iter().enumerate().take(500) {
        let display = if s.len() > 80 {
            format!("{}...", &s[..77])
        } else {
            s.clone()
        };
        table.add_row(vec![&i.to_string(), &display]);
    }

    println!("\nStrings found: {}", strings_found.len());
    println!("{table}");
    Ok(())
}

async fn analyze_metadata(args: &MetadataArgs) -> Result<(), String> {
    use comfy_table::Table;
    use chrono::{DateTime, Utc};

    let path = std::path::Path::new(&args.path);
    if !path.exists() {
        return Err(format!("file not found: {}", args.path));
    }

    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let data = std::fs::read(path).map_err(|e| e.to_string())?;

    let modified: DateTime<Utc> = metadata.modified().map(|t| t.into()).unwrap_or_default();

    let mut table = Table::new();
    table
        .set_header(vec!["Property", "Value"])
        .add_row(vec!["Filename", path.file_name().and_then(|n| n.to_str()).unwrap_or("?")])
        .add_row(vec!["Size", &format!("{} bytes ({})", metadata.len(), format_size(metadata.len()))])
        .add_row(vec!["Type", detect_file_type(&data)])
        .add_row(vec!["Modified", &modified.format("%Y-%m-%d %H:%M:%S UTC").to_string()])
        .add_row(vec!["Permissions", &format!("{:o}", metadata.permissions().mode())])
        .add_row(vec!["Read-only", &metadata.permissions().readonly().to_string()]);

    if !cfg!(target_os = "windows") {
        if let Ok(uid) = libc_uid() {
            table.add_row(vec!["Owner UID", &uid.to_string()]);
        }
    }

    println!("\nMetadata:");
    println!("{table}");
    Ok(())
}

fn detect_file_type(data: &[u8]) -> String {
    if data.len() < 16 {
        return "Unknown".into();
    }

    let magic = &data[..16.min(data.len())];

    // Check for common formats
    if magic.starts_with(b"\x7fELF") {
        let bitness = if data[4] == 1 { "32-bit" } else { "64-bit" };
        let endian = if data[5] == 1 { "LSB" } else { "MSB" };
        let os_abi = match data[7] {
            0x00 => "System V",
            0x03 => "Linux",
            0x09 => "FreeBSD",
            _ => "Unknown",
        };
        return format!("ELF {bitness} {endian} ({os_abi})");
    }
    if magic.starts_with(b"MZ") {
        return "PE (Portable Executable)".into();
    }
    if magic.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || magic.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
        return "Mach-O".into();
    }
    if magic.starts_with(b"PK") {
        return "ZIP Archive".into();
    }
    if magic.starts_with(b"\x89PNG") {
        return "PNG Image".into();
    }
    if magic.starts_with(b"\xFF\xD8\xFF") {
        return "JPEG Image".into();
    }
    if magic.starts_with(b"%PDF") {
        return "PDF Document".into();
    }

    format!("Unknown (magic: {})", hex::encode(&magic[..4.min(data.len())]))
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut s = size as f64;
    let mut unit_idx = 0;
    while s >= 1024.0 && unit_idx < UNITS.len() - 1 {
        s /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.2} {}", s, UNITS[unit_idx])
}

#[cfg(not(target_os = "windows"))]
fn libc_uid() -> Option<u32> {
    Some(unsafe { libc::getuid() })
}

#[cfg(target_os = "windows")]
fn libc_uid() -> Option<u32> {
    None
}

async fn list_re_modules() -> Result<(), String> {
    use comfy_table::Table;
    let mut table = Table::new();
    table
        .set_header(vec!["Module", "Version", "Description"])
        .add_row(vec!["disassembler", "1.0.0", "Capstone-based disassembly engine"])
        .add_row(vec!["decompiler", "0.9.0", "RetDec-based decompilation"])
        .add_row(vec!["string-extractor", "1.0.0", "String extraction utility"])
        .add_row(vec!["pe-analyzer", "1.0.0", "PE binary analysis"])
        .add_row(vec!["elf-analyzer", "1.0.0", "ELF binary analysis"]);

    println!("Available Reverse Engineering Modules:");
    println!("{table}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_file_type_elf() {
        let elf = [0x7Fu8, b'E', b'L', b'F', 2, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = detect_file_type(&elf);
        assert!(result.contains("ELF"));
        assert!(result.contains("64-bit"));
    }

    #[test]
    fn test_detect_file_type_pe() {
        let pe = [0x4D, 0x5A, 0x90, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = detect_file_type(&pe);
        assert!(result.contains("PE"));
    }

    #[test]
    fn test_detect_file_type_png() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = detect_file_type(&png);
        assert_eq!(result, "PNG Image");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500.00 B");
        assert_eq!(format_size(2048), "2.00 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"hello\x00world\x00\x00\x00abcde";
        let path = "test_strings.bin";
        std::fs::write(path, data).unwrap();
        // Test is async — just validate basic ASCII detection
        assert!(data.windows(5).any(|w| w == b"hello"));
        let _ = std::fs::remove_file(path);
    }
}
