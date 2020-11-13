use crate::hmac_sha1::hmac_sha1;

pub fn hotp(key: &[u8], counter: usize, digits: u32) -> u32 {
    let hs = hmac_sha1(key, &counter.to_be_bytes());
    let snum = dt(&hs);
    snum % 10u32.pow(digits)
}

fn dt(hmac_result: &[u8]) -> u32 {
    let offset = hmac_result[19] & 0xf;
    (hmac_result[offset as usize] as u32 & 0x7f) << 24
        | (hmac_result[offset as usize + 1] as u32) << 16
        | (hmac_result[offset as usize + 2] as u32) << 8
        | (hmac_result[offset as usize + 3] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";
    const DIGITS: u32 = 6;

    #[test]
    fn count_0() {
        assert_eq!(hotp(SECRET, 0, DIGITS), 755224);
    }

    #[test]
    fn count_1() {
        assert_eq!(hotp(SECRET, 1, DIGITS), 287082);
    }

    #[test]
    fn count_2() {
        assert_eq!(hotp(SECRET, 2, DIGITS), 359152);
    }

    #[test]
    fn count_3() {
        assert_eq!(hotp(SECRET, 3, DIGITS), 969429);
    }

    #[test]
    fn count_4() {
        assert_eq!(hotp(SECRET, 4, DIGITS), 338314);
    }

    #[test]
    fn count_5() {
        assert_eq!(hotp(SECRET, 5, DIGITS), 254676);
    }

    #[test]
    fn count_6() {
        assert_eq!(hotp(SECRET, 6, DIGITS), 287922);
    }

    #[test]
    fn count_7() {
        assert_eq!(hotp(SECRET, 7, DIGITS), 162583);
    }

    #[test]
    fn count_8() {
        assert_eq!(hotp(SECRET, 8, DIGITS), 399871);
    }

    #[test]
    fn count_9() {
        assert_eq!(hotp(SECRET, 9, DIGITS), 520489);
    }
}
