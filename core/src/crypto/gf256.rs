//! GF(2^8) finite field arithmetic for Reed-Solomon error correction.
//!
//! Uses the AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
//! with primitive element α = 0x03.
//!
//! All operations use log/exp lookup tables for constant-time multiplication.

/// The irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
/// This polynomial is standard for Reed-Solomon codes (QR, DVD, CCSDS).
/// α = 0x02 is primitive for this polynomial.
const POLYNOMIAL: u16 = 0x11D;

/// Primitive element (generator) of the multiplicative group.
#[cfg(test)]
const GENERATOR: u8 = 0x02;

/// Exponential lookup table: EXP[i] = α^i mod p(x), for i in 0..512
/// Extended to 512 entries to avoid modular reduction during multiplication.
static EXP_TABLE: [u8; 512] = build_exp_table();

/// Logarithm lookup table: LOG[α^i] = i, for i in 0..255
/// LOG[0] is undefined (set to 0 as sentinel).
static LOG_TABLE: [u8; 256] = build_log_table();

const fn build_exp_table() -> [u8; 512] {
    let mut table = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0;
    while i < 255 {
        table[i] = val as u8;
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= POLYNOMIAL;
        }
        i += 1;
    }
    // α^255 = 1, extend table for easy modular arithmetic
    while i < 512 {
        table[i] = table[i - 255];
        i += 1;
    }
    table
}

const fn build_log_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut val: u16 = 1;
    let mut i = 0u8;
    while i < 255 {
        table[val as usize] = i;
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= POLYNOMIAL;
        }
        i += 1;
    }
    table
}

/// Addition in GF(2^8) is XOR.
#[inline]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(2^8) is the same as addition (XOR).
#[inline]
pub fn sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(2^8) using log/exp tables.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_a = LOG_TABLE[a as usize] as usize;
    let log_b = LOG_TABLE[b as usize] as usize;
    EXP_TABLE[log_a + log_b]
}

/// Division in GF(2^8): a / b. Panics if b == 0.
#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    let log_a = LOG_TABLE[a as usize] as usize;
    let log_b = LOG_TABLE[b as usize] as usize;
    EXP_TABLE[log_a + 255 - log_b]
}

/// Multiplicative inverse in GF(2^8). Panics if a == 0.
#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "inverse of zero in GF(256)");
    let log_a = LOG_TABLE[a as usize] as usize;
    EXP_TABLE[255 - log_a]
}

/// Exponentiation: a^n in GF(2^8).
pub fn pow(a: u8, n: u32) -> u8 {
    if a == 0 {
        return if n == 0 { 1 } else { 0 };
    }
    if n == 0 {
        return 1;
    }
    let log_a = LOG_TABLE[a as usize] as usize;
    let exp = (log_a * n as usize) % 255;
    EXP_TABLE[exp]
}

/// Returns α^i (the i-th power of the primitive element).
#[inline]
pub fn alpha(i: usize) -> u8 {
    EXP_TABLE[i % 255]
}

/// Evaluate a polynomial at a given point in GF(2^8).
/// Coefficients are in order [c0, c1, c2, ...] where poly(x) = c0 + c1*x + c2*x^2 + ...
pub fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    if coeffs.is_empty() {
        return 0;
    }
    // Horner's method (iterate from highest degree to lowest)
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = add(mul(result, x), c);
    }
    result
}

/// Multiply two polynomials over GF(2^8).
/// Coefficients in ascending degree order.
pub fn poly_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut result = vec![0u8; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            result[i + j] = add(result[i + j], mul(ai, bj));
        }
    }
    result
}

/// Add two polynomials over GF(2^8) (component-wise XOR).
pub fn poly_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().max(b.len());
    let mut result = vec![0u8; len];
    for (i, r) in result.iter_mut().enumerate() {
        let va = if i < a.len() { a[i] } else { 0 };
        let vb = if i < b.len() { b[i] } else { 0 };
        *r = add(va, vb);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exp_table_wraps() {
        // α^255 = 1 (the order of the multiplicative group)
        assert_eq!(EXP_TABLE[0], 1);
        assert_eq!(EXP_TABLE[255], EXP_TABLE[0]);
    }

    #[test]
    fn test_generator() {
        assert_eq!(EXP_TABLE[1], GENERATOR);
    }

    #[test]
    fn test_add_is_xor() {
        assert_eq!(add(0x53, 0xCA), 0x53 ^ 0xCA);
        assert_eq!(add(0, 42), 42);
        assert_eq!(add(42, 42), 0); // self-inverse
    }

    #[test]
    fn test_mul_identity() {
        for i in 0..=255u16 {
            assert_eq!(mul(i as u8, 1), i as u8);
            assert_eq!(mul(1, i as u8), i as u8);
        }
    }

    #[test]
    fn test_mul_zero() {
        for i in 0..=255u16 {
            assert_eq!(mul(i as u8, 0), 0);
            assert_eq!(mul(0, i as u8), 0);
        }
    }

    #[test]
    fn test_mul_commutativity() {
        for a in 1..=10u8 {
            for b in 1..=10u8 {
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn test_mul_associativity() {
        let a = 0x53u8;
        let b = 0xCAu8;
        let c = 0x21u8;
        assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
    }

    #[test]
    fn test_distributivity() {
        let a = 0x53u8;
        let b = 0xCAu8;
        let c = 0x21u8;
        // a * (b + c) = a*b + a*c
        assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
    }

    #[test]
    fn test_inverse() {
        for i in 1..=255u16 {
            let a = i as u8;
            assert_eq!(mul(a, inv(a)), 1, "a={a}: a * inv(a) should be 1");
        }
    }

    #[test]
    fn test_div() {
        for a in 1..=10u8 {
            for b in 1..=10u8 {
                let q = div(a, b);
                assert_eq!(mul(q, b), a, "{a} / {b} = {q}, but {q} * {b} != {a}");
            }
        }
    }

    #[test]
    fn test_pow() {
        let a = 0x03u8; // generator
        assert_eq!(pow(a, 0), 1);
        assert_eq!(pow(a, 1), a);
        assert_eq!(pow(a, 2), mul(a, a));
        assert_eq!(pow(a, 255), 1); // order of multiplicative group
    }

    #[test]
    fn test_alpha() {
        assert_eq!(alpha(0), 1);
        assert_eq!(alpha(1), GENERATOR);
    }

    #[test]
    fn test_poly_eval() {
        // p(x) = 1 + 2x + 3x^2
        let p = vec![1, 2, 3];
        assert_eq!(poly_eval(&p, 0), 1); // p(0) = 1
    }

    #[test]
    fn test_poly_mul() {
        // (1 + x) * (1 + x) in GF(2^8)
        // = 1 + x + x + x^2 = 1 + 0 + x^2 (since x + x = 0 in GF(2^8))
        let a = vec![1, 1];
        let result = poly_mul(&a, &a);
        assert_eq!(result, vec![1, 0, 1]);
    }

    #[test]
    fn test_sub_equals_add() {
        for a in 0..=255u16 {
            for b in 0..=10u16 {
                assert_eq!(sub(a as u8, b as u8), add(a as u8, b as u8));
            }
        }
    }
}
