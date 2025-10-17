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

/// Simple trait used throughout the codebase to provide portable array operations
pub trait ByteArray: Sized + Zeroize + PartialEq + Debug + Clone {
    /// Initialize a new array with zeros
    fn new_zero() -> Self;
    /// Initialize a new array by filling it with the given element
    fn new_with(_: u8) -> Self;
    /// Initialize a new array by copying it from the given slice
    ///
    /// # Panics
    /// * Panics if the slice length does not match this array length
    fn from_slice(_: &[u8]) -> Self;
    /// Array length
    fn len() -> usize;
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
    pub fn new(a: A) -> SensitiveByteArray<A> {
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
    fn new_zero() -> Self {
        Self::new(A::new_zero())
    }

    fn new_with(a: u8) -> Self {
        Self::new(A::new_with(a))
    }

    fn from_slice(s: &[u8]) -> Self {
        Self::new(A::from_slice(s))
    }

    fn len() -> usize {
        A::len()
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
pub struct HeapArray<const C: usize>(alloc::vec::Vec<u8>);

#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl<const C: usize> ByteArray for HeapArray<C> {
    fn new_zero() -> Self {
        Self::new_with(0)
    }

    fn new_with(x: u8) -> Self {
        let v = alloc::vec![x; C];
        Self(v)
    }

    fn from_slice(s: &[u8]) -> Self {
        let mut v = alloc::vec![0; C];
        v.as_mut_slice().copy_from_slice(s);
        Self(v)
    }

    fn len() -> usize {
        C
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<const C: usize> ByteArray for ArrayVec<u8, C> {
    fn new_zero() -> Self {
        Self::new_with(0)
    }

    fn new_with(x: u8) -> Self {
        let mut a = ArrayVec::<u8, C>::new();
        for _ in 0..C {
            a.push(x);
        }
        a
    }

    fn from_slice(s: &[u8]) -> Self {
        let mut a = Self::new_zero();
        a.copy_from_slice(s);
        a
    }

    fn len() -> usize {
        C
    }

    fn as_slice(&self) -> &[u8] {
        self
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

macro_rules! impl_array {
    ($array:ty, $w:literal) => {
        impl $array for [u8; $w] {
            fn new_zero() -> Self {
                [0u8; $w]
            }
            fn new_with(x: u8) -> Self {
                [x; $w]
            }
            fn from_slice(data: &[u8]) -> Self {
                let mut a = [0u8; $w];
                a.copy_from_slice(data);
                a
            }
            fn len() -> usize {
                $w
            }
            fn as_slice(&self) -> &[u8] {
                self
            }
            fn as_mut(&mut self) -> &mut [u8] {
                self
            }
        }
    };
}

// Implement ByteArray for the most common array sizes
impl_array!(ByteArray, 8);
impl_array!(ByteArray, 16);
impl_array!(ByteArray, 32);
impl_array!(ByteArray, 64);
impl_array!(ByteArray, 128);
impl_array!(ByteArray, 256);
impl_array!(ByteArray, 512);
impl_array!(ByteArray, 1024);

// These are for Kyber
impl_array!(ByteArray, 768);
impl_array!(ByteArray, 800);
impl_array!(ByteArray, 1088);
impl_array!(ByteArray, 1184);
impl_array!(ByteArray, 1568);
impl_array!(ByteArray, 1632);
impl_array!(ByteArray, 2400);
impl_array!(ByteArray, 3168);
