use core::num::NonZeroU32;

use rand_core::{CryptoRng, RngCore};

const RNG_FAILURE_MSG: &str = "Clatter default RNG: system failure";

/// Default system RNG provided by [`getrandom`]
#[derive(Default, Clone)]
pub struct DefaultRng;

impl RngCore for DefaultRng {
    fn next_u32(&mut self) -> u32 {
        getrandom::u32().expect(RNG_FAILURE_MSG)
    }

    fn next_u64(&mut self) -> u64 {
        getrandom::u64().expect(RNG_FAILURE_MSG)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect(RNG_FAILURE_MSG);
    }

    /// Fill dest entirely with random data
    ///
    /// Returns the encapsulated raw system error code or -1 ([`u32::MAX`]) if error code is not available.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::fill(dest).map_err(|e| {
            let raw_err = e.raw_os_error().unwrap_or(-1) as u32;
            let errno = NonZeroU32::new(raw_err).unwrap_or(NonZeroU32::new(u32::MAX).unwrap());
            rand_core::Error::from(errno)
        })
    }
}

// Getrandom provides cryptographically secure random numbers
impl CryptoRng for DefaultRng {}
