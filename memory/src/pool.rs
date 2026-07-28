//! Object pool and memory pool implementations for zero-allocation hot paths.
//! Provides thread-local and shared memory pools for reusing allocations.

use crossbeam::queue::SegQueue;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A lock-free object pool for reusing allocations of type `T`.
/// Useful for frequently allocated objects in hot paths.
#[derive(Debug)]
pub struct ObjectPool<T: Default + Send + 'static> {
    inner: SegQueue<Box<T>>,
    allocated: AtomicUsize,
    max_size: usize,
    _marker: PhantomData<T>,
}

impl<T: Default + Send + 'static> ObjectPool<T> {
    /// Create a new object pool with the given maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: SegQueue::new(),
            allocated: AtomicUsize::new(0),
            max_size,
            _marker: PhantomData,
        }
    }

    /// Acquire an object from the pool, or create a new one if empty.
    pub fn acquire(&self) -> Box<T> {
        self.inner
            .try_pop()
            .unwrap_or_else(|| {
                self.allocated.fetch_add(1, Ordering::Relaxed);
                Box::new(T::default())
            })
    }

    /// Return an object to the pool for reuse.
    pub fn release(&self, obj: Box<T>) {
        if self.allocated.load(Ordering::Relaxed) <= self.max_size {
            self.inner.push(obj);
        }
        // If pool is full, the Box<T> is dropped (freed) normally.
    }

    /// Number of objects currently in the pool.
    pub fn available(&self) -> usize {
        self.inner.len()
    }

    /// Total number of objects allocated by this pool.
    pub fn total_allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }
}

/// A byte buffer pool for reusing byte vectors.
/// Reduces allocation churn for I/O and network operations.
#[derive(Debug, Clone)]
pub struct BufferPool {
    inner: Arc<SegQueue<Vec<u8>>>,
    buffer_size: usize,
    max_buffers: usize,
    allocated: Arc<AtomicUsize>,
}

impl BufferPool {
    /// Create a new buffer pool with buffers of the given size.
    pub fn new(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            inner: Arc::new(SegQueue::new()),
            buffer_size,
            max_buffers,
            allocated: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Acquire a buffer from the pool, or create a new one.
    pub fn acquire(&self) -> Vec<u8> {
        self.inner
            .try_pop()
            .unwrap_or_else(|| {
                self.allocated.fetch_add(1, Ordering::Relaxed);
                Vec::with_capacity(self.buffer_size)
            })
    }

    /// Return a buffer to the pool for reuse.
    pub fn release(&self, mut buf: Vec<u8>) {
        buf.clear();
        if self.allocated.load(Ordering::Relaxed) <= self.max_buffers {
            self.inner.push(buf);
        }
    }

    /// Number of buffers currently in the pool.
    pub fn available(&self) -> usize {
        self.inner.len()
    }

    /// Total number of buffers allocated by this pool.
    pub fn total_allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug, PartialEq)]
    struct TestObject {
        value: i32,
    }

    #[test]
    fn test_object_pool_basic() {
        let pool = ObjectPool::<TestObject>::new(10);
        let obj = pool.acquire();
        assert_eq!(obj.value, 0);
        assert_eq!(pool.total_allocated(), 1);
        pool.release(obj);
        // Re-acquire — should come from pool
        let obj2 = pool.acquire();
        assert_eq!(pool.allocated.load(Ordering::Relaxed), 1);
        drop(obj2);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(4096, 10);
        let buf = pool.acquire();
        assert_eq!(buf.capacity(), 4096);
        assert_eq!(pool.total_allocated(), 1);
        pool.release(buf);
        let buf2 = pool.acquire();
        assert_eq!(pool.total_allocated(), 1);
        drop(buf2);
    }

    #[test]
    fn test_pool_capacity_limit() {
        let pool = ObjectPool::<TestObject>::new(2);
        let o1 = pool.acquire();
        let o2 = pool.acquire();
        pool.release(o1);
        pool.release(o2);
        assert_eq!(pool.available(), 2);
        // This one will be dropped since pool is full
        let o3 = pool.acquire();
        pool.release(o3);
        assert_eq!(pool.available(), 2);
    }
}
