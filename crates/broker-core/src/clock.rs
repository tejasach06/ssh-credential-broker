use std::time::Duration;

/// Monotonic time whose elapsed duration includes system suspend on supported platforms.
/// Implementations must never move backwards. This seam is also used by deterministic tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

pub struct ContinuousClock {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    origin: std::time::Instant,
}
impl ContinuousClock {
    pub fn new() -> Self {
        Self {
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            origin: std::time::Instant::now(),
        }
    }
}
impl Default for ContinuousClock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock for ContinuousClock {
    #[cfg(target_os = "linux")]
    fn now(&self) -> Duration {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_BOOTTIME includes suspended time; CLOCK_MONOTONIC does not on Linux.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
        assert_eq!(result, 0, "continuous monotonic clock unavailable");
        assert!(
            time.tv_sec >= 0 && time.tv_nsec >= 0,
            "continuous monotonic clock invalid"
        );
        Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
    }
    #[cfg(target_os = "macos")]
    fn now(&self) -> Duration {
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        extern "C" {
            fn mach_continuous_time() -> u64;
            fn mach_timebase_info(info: *mut Timebase) -> i32;
        }
        static SCALE: std::sync::LazyLock<(u32, u32)> = std::sync::LazyLock::new(|| {
            let mut scale = Timebase { numer: 0, denom: 0 };
            let result = unsafe { mach_timebase_info(&mut scale) };
            assert!(
                result == 0 && scale.denom != 0,
                "continuous monotonic clock unavailable"
            );
            (scale.numer, scale.denom)
        });
        let (numer, denom) = *SCALE;
        let ticks = unsafe { mach_continuous_time() };
        let nanos = u128::from(ticks) * u128::from(numer) / u128::from(denom);
        Duration::new(
            (nanos / 1_000_000_000) as u64,
            (nanos % 1_000_000_000) as u32,
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn now(&self) -> Duration {
        // Portable unit-test fallback only. The daemon rejects unsupported platforms.
        self.origin.elapsed()
    }
}
