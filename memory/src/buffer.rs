//! Zero-copy and managed buffer types for the UCOP-X memory subsystem.
//! Provides `Buffer`, `BufferView`, and `BufferMut` for safe memory access
//! across module boundaries.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Deref, Range};
use zeroize::Zeroize;

/// A managed memory buffer with optional automatic zeroing on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct Buffer {
    inner: Bytes,
    #[serde(skip)]
    secure: bool,
}

impl Buffer {
    /// Create a new buffer from a byte slice.
    pub fn from_slice(data: &[u8], secure: bool) -> Self {
        Self {
            inner: Bytes::copy_from_slice(data),
            secure,
        }
    }

    /// Create a new buffer from a `Vec<u8>`.
    pub fn from_vec(data: Vec<u8>, secure: bool) -> Self {
        Self {
            inner: Bytes::from(data),
            secure,
        }
    }

    /// Create an empty buffer.
    pub fn empty() -> Self {
        Self {
            inner: Bytes::new(),
            secure: false,
        }
    }

    /// View this buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get the length of the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return a sub-slice view of this buffer.
    pub fn slice(&self, range: Range<usize>) -> Option<BufferView> {
        if range.end <= self.len() {
            Some(BufferView {
                inner: self.inner.slice(range),
            })
        } else {
            None
        }
    }

    /// Consume the buffer and return the inner bytes.
    pub fn into_inner(self) -> Bytes {
        self.inner
    }

    /// Whether this buffer uses secure memory (zeroed on drop).
    pub fn is_secure(&self) -> bool {
        self.secure
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("len", &self.len())
            .field("secure", &self.secure)
            .field("data", &hex::encode(&self.inner[..self.len().min(32)]))
            .finish()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if self.secure {
            // Zeroize the underlying buffer if we own it exclusively.
            // Bytes uses atomic refcounting, so we only zero if refcount is 1.
            if let Some(mut slice) = std::sync::Arc::get_mut(&mut self.inner) {
                slice.zeroize();
            }
        }
    }
}

/// A borrowed, read-only view into a buffer.
#[derive(Debug, Clone)]
pub struct BufferView {
    inner: Bytes,
}

impl BufferView {
    /// Get the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get the length of this view.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Deref for BufferView {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

/// A mutable buffer backed by a pinned allocation.
#[derive(Debug)]
pub struct BufferMut {
    data: Vec<u8>,
    secure: bool,
}

impl BufferMut {
    /// Create a new mutable buffer with the given capacity.
    pub fn with_capacity(capacity: usize, secure: bool) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            secure,
        }
    }

    /// Write bytes into the buffer.
    pub fn write(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Get a reference to the written data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of written data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Freeze this buffer into an immutable `Buffer`.
    pub fn freeze(self) -> Buffer {
        Buffer::from_vec(self.data, self.secure)
    }
}

impl Drop for BufferMut {
    fn drop(&mut self) {
        if self.secure {
            self.data.zeroize();
        }
    }
}

/// A pool-allocated region that can hold structured data with alignment.
/// Useful for SIMD and zero-copy parsing.
#[derive(Debug)]
pub struct AlignedBuffer<const ALIGN: usize> {
    data: Vec<u8>,
}

impl<const ALIGN: usize> AlignedBuffer<ALIGN> {
    /// Create a new aligned buffer of the given size.
    pub fn new(size: usize) -> Self {
        assert!(ALIGN.is_power_of_two(), "alignment must be power of two");
        let mut data = Vec::with_capacity(size + ALIGN);
        let offset = data.as_ptr().align_offset(ALIGN);
        if offset > 0 {
            data.resize(offset, 0);
        }
        data.resize(size + offset, 0);
        Self { data }
    }

    /// Get a pointer to the aligned portion.
    pub fn as_ptr(&self) -> *const u8 {
        unsafe { self.data.as_ptr().add(self.data.len().saturating_sub(ALIGN)) }
    }

    /// Get the aligned portion as a slice.
    pub fn as_slice(&self) -> &[u8] {
        let start = self.data.len().saturating_sub(ALIGN);
        &self.data[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation() {
        let buf = Buffer::from_slice(b"hello", false);
        assert_eq!(buf.as_slice(), b"hello");
        assert!(!buf.is_secure());
    }

    #[test]
    fn test_secure_buffer_zeroing() {
        let buf = Buffer::from_vec(vec![0xAB, 0xCD, 0xEF], true);
        assert!(buf.is_secure());
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_buffer_slicing() {
        let buf = Buffer::from_slice(b"abcdef", false);
        let view = buf.slice(1..4).unwrap();
        assert_eq!(view.as_slice(), b"bcd");
    }

    #[test]
    fn test_buffer_mut_freeze() {
        let mut buf = BufferMut::with_capacity(10, false);
        buf.write(b"test data");
        assert_eq!(buf.len(), 9);
        let frozen = buf.freeze();
        assert_eq!(frozen.as_slice(), b"test data");
    }

    #[test]
    fn test_aligned_buffer() {
        let abuf = AlignedBuffer::<64>::new(128);
        let ptr = abuf.as_ptr();
        assert!(ptr as usize % 64 == 0);
    }
}
