use core::fmt::Debug;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Simple trait used throughout the codebase to provide
/// portable array operations
pub trait ByteArray: Sized + Zeroize + PartialEq + Debug {
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
    /// Borrow this array as mutable
    fn as_mut(&mut self) -> &mut [u8];
    /// Clone this array
    fn clone(&self) -> Self {
        Self::from_slice(self.as_slice())
    }
}

/// Encapsulation for all [`ByteArray`] types that is automatically zeroized on drop.
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

macro_rules! impl_array {
    ($array:ty, $w:expr) => {
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

// Hear me out:
// If we have to manually define the sizes for all crypto-related arrays,
// many indexing and sizing related errors can be eliminated completely.
//
// This adds a bit of labor for the developers, but it is worth it. To add
// heap allocation support, we can use this same approach with any statically-sized
// heap-allocated array type we wish. Either make one of our own or use existing
// crates.
//
// TL;DR
// Let's not use Vecs

impl_array!(ByteArray, 32);
impl_array!(ByteArray, 64);
impl_array!(ByteArray, 128);

// These are for Kyber
impl_array!(ByteArray, 768);
impl_array!(ByteArray, 800);
impl_array!(ByteArray, 1088);
impl_array!(ByteArray, 1184);
impl_array!(ByteArray, 1568);
impl_array!(ByteArray, 1632);
impl_array!(ByteArray, 2400);
impl_array!(ByteArray, 3168);
