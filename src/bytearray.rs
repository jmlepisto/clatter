//! Generic array utilities used throughout the crate
//!
//! This module provides a compatibility trait [`ByteArray`] along with some
//! helper implementations. Generally all algorithmic operations in this crate
//! are operated on arguments which implements [`ByteArray`]. This allows us to
//! easily support different environments and allocation modes.
//!
//! # Contents
//! * [`ByteArray`] - Common trait for all arrays
//! * [`SensitiveByteArray`] - Wrapper implementation for sensitive data which is zeroized on drop
//! * [`HeapArray`] - Statically sized heap-allocated array that implements [`ByteArray`]. Available with the `alloc` crate feature.

use core::fmt::Debug;

use arrayvec::ArrayVec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Simple trait used throughout the codebase to provide portable array operations.
///
/// The trait exposes an associated constant [`LENGTH`] which is known at compile-time,
/// allowing the array length to be used in const contexts without explicitly specifying
/// a const generic parameter everywhere.
pub trait ByteArray: Sized + Zeroize + PartialEq + Debug + Clone {
    /// Array length
    const LENGTH: usize;

    /// Initialize a new array with zeros
    fn new_zero() -> Self;
    /// Initialize a new array by filling it with the given element
    fn new_with(_: u8) -> Self;
    /// Initialize a new array by copying it from the given slice
    ///
    /// # Panics
    /// Panics if the slice length does not match this array length
    fn from_slice(_: &[u8]) -> Self;
    /// Array length
    fn len() -> usize {
        Self::LENGTH
    }
    /// Borrow this array as a slice
    fn as_slice(&self) -> &[u8];
    /// Borrow this array as a mutable slice
    fn as_mut(&mut self) -> &mut [u8];
}

/// Encapsulation for all [`ByteArray`] types that is automatically zeroized on drop.
///
/// Also implements [`ByteArray`] itself so this is a drop-in replacement for any data
/// type used by the crypto implementations.
#[derive(ZeroizeOnDrop, Zeroize, Clone, PartialEq, Debug)]
pub struct SensitiveByteArray<A: ByteArray>(A);

impl<A: ByteArray> SensitiveByteArray<A> {
    /// Encapsulate the given [`ByteArray`]
    pub fn new(a: A) -> Self {
        Self(a)
    }
}

impl<A: ByteArray> core::ops::Deref for SensitiveByteArray<A> {
    type Target = A;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: ByteArray> core::ops::DerefMut for SensitiveByteArray<A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<A: ByteArray> ByteArray for SensitiveByteArray<A> {
    const LENGTH: usize = A::LENGTH;

    fn new_zero() -> Self {
        Self::new(A::new_zero())
    }

    fn new_with(a: u8) -> Self {
        Self::new(A::new_with(a))
    }

    fn from_slice(s: &[u8]) -> Self {
        Self::new(A::from_slice(s))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

/// Statically sized heap allocated array
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
#[derive(Zeroize, Debug, PartialEq, Clone)]
pub struct HeapArray<const N: usize>(alloc::vec::Vec<u8>);

#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl<const N: usize> ByteArray for HeapArray<N> {
    const LENGTH: usize = N;

    fn new_zero() -> Self {
        Self::new_with(0)
    }

    fn new_with(x: u8) -> Self {
        let v = alloc::vec![x; N];
        Self(v)
    }

    fn from_slice(s: &[u8]) -> Self {
        assert_eq!(s.len(), N);
        let mut v = alloc::vec![0; N];
        v.as_mut_slice().copy_from_slice(s);
        Self(v)
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<const N: usize> ByteArray for ArrayVec<u8, N> {
    const LENGTH: usize = N;

    fn new_zero() -> Self {
        Self::new_with(0)
    }

    fn new_with(x: u8) -> Self {
        let mut a = ArrayVec::<u8, N>::new();
        for _ in 0..N {
            a.push(x);
        }
        a
    }

    fn from_slice(s: &[u8]) -> Self {
        assert_eq!(s.len(), N);
        let mut a = Self::new_zero();
        a.copy_from_slice(s);
        a
    }

    fn as_slice(&self) -> &[u8] {
        self
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

/// Implement `ByteArray` for fixed-size `[u8; N]` arrays
impl<const N: usize> ByteArray for [u8; N] {
    const LENGTH: usize = N;

    fn new_zero() -> Self {
        [0u8; N]
    }

    fn new_with(x: u8) -> Self {
        [x; N]
    }

    fn from_slice(data: &[u8]) -> Self {
        assert_eq!(data.len(), N);
        let mut a = [0u8; N];
        a.copy_from_slice(data);
        a
    }

    fn as_slice(&self) -> &[u8] {
        self
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}
