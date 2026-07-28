//! Filesystem forensics - NTFS, FAT32, ext4, and APFS artifact extraction.

/// Supported filesystem types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemType {
    Ntfs,
    Fat32,
    Ext4,
    Apfs,
    Unknown,
}

/// A filesystem entry (file or directory).
#[derive(Debug, Clone)]
pub struct FileSystemEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: u64,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub permissions: String,
    pub inode: u64,
}

/// Filesystem metadata.
#[derive(Debug, Clone)]
pub struct FileSystemMetadata {
    pub fs_type: FileSystemType,
    pub volume_name: String,
    pub total_space: u64,
    pub used_space: u64,
    pub free_space: u64,
    pub block_size: u32,
    pub entries: Vec<FileSystemEntry>,
}

/// Filesystem forensics analyzer.
#[derive(Debug, Default)]
pub struct FileSystemAnalyzer;

impl FileSystemAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Recursively list files in a directory for forensic analysis.
    pub fn list_files(&self, path: &std::path::Path) -> Result<Vec<FileSystemEntry>, String> {
        let mut entries = Vec::new();

        if path.is_dir() {
            for entry in walkdir::WalkDir::new(path) {
                let entry = entry.map_err(|e| e.to_string())?;
                let metadata = entry.metadata().map_err(|e| e.to_string())?;

                let created = metadata.created().ok().map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                });

                let modified = metadata.modified().ok().map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                });

                entries.push(FileSystemEntry {
                    name: entry.file_name().to_string_lossy().into(),
                    path: entry.path().to_string_lossy().into(),
                    is_directory: metadata.is_dir(),
                    size: metadata.len(),
                    created,
                    modified,
                    accessed: None,
                    permissions: format!("{:o}", metadata.permissions().readonly() as u8),
                    inode: 0,
                });
            }
        }

        Ok(entries)
    }

    /// Extract files by extension pattern.
    pub fn find_by_extension(
        &self,
        path: &std::path::Path,
        extension: &str,
    ) -> Result<Vec<FileSystemEntry>, String> {
        let all = self.list_files(path)?;
        Ok(all
            .into_iter()
            .filter(|e| e.name.ends_with(extension))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_by_extension_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let analyzer = FileSystemAnalyzer::new();
        let results = analyzer.find_by_extension(dir.path(), ".txt").unwrap();
        assert!(results.is_empty());
    }
}
