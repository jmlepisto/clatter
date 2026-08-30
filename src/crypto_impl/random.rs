use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

#[cfg(all(feature = "getrandom", not(feature = "rand")))]
const RNG_FAILURE_MSG: &str = "Clatter default RNG: system failure";

/// Default RNG source.
///
/// Uses [`rand::rng()`] (thread RNG) when the `rand` feature is enabled.
#[cfg(feature = "rand")]
#[derive(Default, Clone)]
pub struct DefaultRng(());

/// Default RNG source.
///
/// Uses [`getrandom`] directly when `getrandom` is enabled and `rand` is disabled.
///
/// # Panics:
///
/// Due to the nature of `getrandom`, this RNG will panic if the system RNG fails.
/// On all major systems this is truly exceptional and should never happen in practice.
#[cfg(all(feature = "getrandom", not(feature = "rand")))]
#[derive(Default, Clone)]
pub struct DefaultRng(());

#[cfg(feature = "rand")]
impl TryRng for DefaultRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand::rng().try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand::rng().try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        rand::rng().try_fill_bytes(dest)
    }
}

#[cfg(all(feature = "getrandom", not(feature = "rand")))]
impl TryRng for DefaultRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(getrandom::u32().expect(RNG_FAILURE_MSG))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(getrandom::u64().expect(RNG_FAILURE_MSG))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        Ok(getrandom::fill(dest).expect(RNG_FAILURE_MSG))
    }
}

// Getrandom provides cryptographically secure random numbers
impl TryCryptoRng for DefaultRng {}
