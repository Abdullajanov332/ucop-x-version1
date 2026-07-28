//! IOC (Indicator of Compromise) parsing and validation.

use crate::IoCType;

/// Parse an IOC value and detect its type.
pub fn detect_ioc_type(value: &str) -> Option<IoCType> {
    // Check for IP address (IPv4)
    if value.chars().filter(|c| *c == '.').count() == 3
        && value.split('.').all(|octet| octet.parse::<u8>().is_ok())
    {
        return Some(IoCType::IpAddress);
    }

    // Check for SHA-256 hash
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Hash);
    }

    // Check for SHA-1 hash
    if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Hash);
    }

    // Check for MD5 hash
    if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Hash);
    }

    // Check for URL
    if value.starts_with("http://") || value.starts_with("https://") {
        return Some(IoCType::Url);
    }

    // Check for domain (simple check)
    if value.contains('.') && !value.contains(' ') && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Some(IoCType::Domain);
    }

    // Check for email
    if value.contains('@') && value.contains('.') {
        return Some(IoCType::Email);
    }

    // Check for CVE
    if value.starts_with("CVE-") || value.starts_with("cve-") {
        return Some(IoCType::Cve);
    }

    None
}

/// Validate an IOC value based on its type.
pub fn validate_ioc(ioc_type: IoCType, value: &str) -> bool {
    match ioc_type {
        IoCType::IpAddress => {
            let parts: Vec<&str> = value.split('.').collect();
            parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
        }
        IoCType::Hash => {
            (value.len() == 32 || value.len() == 40 || value.len() == 64)
                && value.chars().all(|c| c.is_ascii_hexdigit())
        }
        IoCType::Domain => {
            !value.is_empty()
                && value.contains('.')
                && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        }
        IoCType::Url => {
            value.starts_with("http://") || value.starts_with("https://")
        }
        IoCType::Email => {
            value.contains('@') && value.contains('.')
        }
        IoCType::Cve => {
            value.starts_with("CVE-") || value.starts_with("cve-")
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ip() {
        assert_eq!(detect_ioc_type("192.168.1.1"), Some(IoCType::IpAddress));
        assert!(detect_ioc_type("256.256.256.256").is_none());
    }

    #[test]
    fn test_detect_hash() {
        assert_eq!(
            detect_ioc_type("a".."a".repeat(32).len()),
            Some(IoCType::Hash)
        );
    }

    #[test]
    fn test_detect_ioc_type() {
        assert_eq!(detect_ioc_type("evil.example.com"), Some(IoCType::Domain));
        assert_eq!(detect_ioc_type("https://evil.com/payload"), Some(IoCType::Url));
        assert_eq!(detect_ioc_type("user@evil.com"), Some(IoCType::Email));
        assert_eq!(detect_ioc_type("CVE-2024-1234"), Some(IoCType::Cve));
    }
}
