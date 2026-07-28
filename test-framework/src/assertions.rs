//! Custom assertions for security testing.

/// Assert that a slice contains a specific byte pattern.
pub fn assert_contains(data: &[u8], pattern: &[u8]) -> Result<(), String> {
    if data.windows(pattern.len()).any(|w| w == pattern) {
        Ok(())
    } else {
        Err(format!("data does not contain pattern {:02x?}", pattern))
    }
}

/// Assert that a slice does NOT contain a specific byte pattern.
pub fn assert_not_contains(data: &[u8], pattern: &[u8]) -> Result<(), String> {
    if data.windows(pattern.len()).any(|w| w == pattern) {
        Err(format!("data contains forbidden pattern {:02x?}", pattern))
    } else {
        Ok(())
    }
}

/// Assert that a value is within a range (inclusive).
pub fn assert_in_range<T: PartialOrd + std::fmt::Display>(value: T, min: T, max: T) -> Result<(), String> {
    if value >= min && value <= max {
        Ok(())
    } else {
        Err(format!("value {value} not in range [{min}, {max}]"))
    }
}

/// Assert that a function completes within a timeout.
pub fn assert_timeout<F, T>(timeout: std::time::Duration, f: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    use std::time::Instant;
    let start = Instant::now();
    let result = f();
    if start.elapsed() > timeout {
        Err(format!("function took {:?}, exceeded {:?}", start.elapsed(), timeout))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_contains_pattern() {
        let data = b"hello world this is a test";
        assert!(assert_contains(data, b"world").is_ok());
        assert!(assert_contains(data, b"missing").is_err());
    }

    #[test]
    fn test_assert_in_range() {
        assert!(assert_in_range(5, 0, 10).is_ok());
        assert!(assert_in_range(15, 0, 10).is_err());
    }

    #[test]
    fn test_assert_timeout() {
        let result = assert_timeout(std::time::Duration::from_secs(1), || 42);
        assert_eq!(result.unwrap(), 42);
    }
}
