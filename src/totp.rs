use crate::hotp;

pub fn totp(key: &[u8], current_unix_time: usize, t0: usize, x: usize, return_digits: u32) -> u32 {
    let t = (current_unix_time - t0) / x;
    hotp::hotp(key, t, return_digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: usize = 30;
    const KEY: &[u8] = b"12345678901234567890";
    const T0: usize = 0;
    const SIZE: u32 = 8;

    #[test]
    fn test_case_1() {
        assert_eq!(totp(KEY, 59, T0, X, SIZE), 94287082);
    }

    #[test]
    fn test_case_2() {
        assert_eq!(totp(KEY, 1111111109, T0, X, SIZE), 7081804);
    }

    #[test]
    fn test_case_3() {
        assert_eq!(totp(KEY, 1111111111, T0, X, SIZE), 14050471);
    }

    #[test]
    fn test_case_4() {
        assert_eq!(totp(KEY, 1234567890, T0, X, SIZE), 89005924);
    }

    #[test]
    fn test_case_5() {
        assert_eq!(totp(KEY, 2000000000, T0, X, SIZE), 69279037);
    }

    #[test]
    fn test_case_6() {
        assert_eq!(totp(KEY, 20000000000, T0, X, SIZE), 65353130);
    }
}
