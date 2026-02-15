//! Reed-Solomon error correction codec over GF(2^8).
//!
//! Implements RS(n, k) where:
//! - n = block length (up to 255 for GF(256))
//! - k = message length
//! - t = (n - k) / 2 = error correction capacity
//!
//! The code can correct up to t symbol errors where each symbol is one byte.
//!
//! # Construction
//!
//! Generator polynomial: g(x) = ∏_{i=0}^{2t-1} (x - α^i)
//! Encoding: systematic — message bytes followed by 2t parity bytes.
//! Decoding: syndrome → Berlekamp-Massey → Chien search → Forney.
//!
//! # Polynomial convention
//!
//! Codeword array `[c_0, c_1, ..., c_{n-1}]` represents the polynomial
//! `c(x) = c_0·x^{n-1} + c_1·x^{n-2} + ... + c_{n-1}`.
//! Array index `i` holds the coefficient of `x^{n-1-i}`.

use super::gf256;

/// Reed-Solomon codec for a specific (n, k) configuration.
pub struct ReedSolomon {
    /// Block length (n ≤ 255)
    n: usize,
    /// Message length
    k: usize,
    /// Number of parity symbols (n - k), must be even
    parity_len: usize,
    /// Error correction capacity t = parity_len / 2
    t: usize,
    /// Generator polynomial coefficients in ascending degree order
    generator: Vec<u8>,
}

/// Error returned when decoding fails (too many errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError;

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Reed-Solomon decoding failed: too many errors")
    }
}

impl ReedSolomon {
    /// Create a new RS(n, k) codec.
    ///
    /// - `n`: block length, must be ≤ 255
    /// - `k`: message length, must be < n
    /// - `n - k` must be even (so t = (n-k)/2 is integral)
    pub fn new(n: usize, k: usize) -> Self {
        assert!(n <= 255, "block length must be ≤ 255");
        assert!(k < n, "message length must be less than block length");
        let parity_len = n - k;
        assert!(parity_len % 2 == 0, "parity length must be even");
        let t = parity_len / 2;

        // Build generator polynomial: g(x) = ∏(x - α^i) for i = 0..2t-1
        // Start with g(x) = 1
        let mut gen = vec![1u8];
        for i in 0..parity_len {
            // Multiply by (x - α^i) = (x + α^i) since subtraction = addition in GF(2^8)
            // Polynomial (α^i + x): coefficients [α^i, 1] in ascending degree
            let root = gf256::alpha(i);
            let mut new_gen = vec![0u8; gen.len() + 1];
            for (j, &coeff) in gen.iter().enumerate() {
                new_gen[j] = gf256::add(new_gen[j], gf256::mul(coeff, root));
                new_gen[j + 1] = gf256::add(new_gen[j + 1], coeff);
            }
            gen = new_gen;
        }

        Self {
            n,
            k,
            parity_len,
            t,
            generator: gen,
        }
    }

    /// Error correction capacity.
    pub fn correction_capacity(&self) -> usize {
        self.t
    }

    /// Encode a message of length k into a codeword of length n.
    ///
    /// Uses systematic encoding: output = [message | parity].
    pub fn encode(&self, message: &[u8]) -> Vec<u8> {
        assert_eq!(message.len(), self.k, "message length must be k={}", self.k);

        // Systematic encoding via synthetic division of m(x)·x^{2t} by g(x).
        // The remainder becomes the parity bytes.
        let mut remainder = vec![0u8; self.parity_len];

        for &msg_byte in message {
            let feedback = gf256::add(msg_byte, remainder[self.parity_len - 1]);
            for j in (1..self.parity_len).rev() {
                remainder[j] =
                    gf256::add(remainder[j - 1], gf256::mul(feedback, self.generator[j]));
            }
            remainder[0] = gf256::mul(feedback, self.generator[0]);
        }

        let mut codeword = Vec::with_capacity(self.n);
        codeword.extend_from_slice(message);
        // Parity: remainder[parity_len-1] is highest degree parity coefficient
        for &r in remainder.iter().rev() {
            codeword.push(r);
        }
        codeword
    }

    /// Decode a received word of length n, correcting up to t symbol errors.
    ///
    /// Returns the decoded message of length k, or `DecodeError` if uncorrectable.
    pub fn decode(&self, received: &[u8]) -> Result<Vec<u8>, DecodeError> {
        assert_eq!(
            received.len(),
            self.n,
            "received length must be n={}",
            self.n
        );

        // Step 1: Compute syndromes S_i = r(α^i) for i = 0..2t-1
        let syndromes = self.compute_syndromes(received);

        // If all syndromes are zero, no errors
        if syndromes.iter().all(|&s| s == 0) {
            return Ok(received[..self.k].to_vec());
        }

        // Step 2: Berlekamp-Massey to find error locator polynomial
        let error_locator = self.berlekamp_massey(&syndromes);

        // Number of errors
        let num_errors = error_locator.len() - 1;
        if num_errors > self.t {
            return Err(DecodeError);
        }

        // Step 3: Chien search to find error positions
        let error_positions = self.chien_search(&error_locator, num_errors)?;

        // Step 4: Forney algorithm to find error magnitudes
        let error_magnitudes =
            self.forney_algorithm(&syndromes, &error_locator, &error_positions)?;

        // Step 5: Correct errors
        let mut corrected = received.to_vec();
        for (&pos, &mag) in error_positions.iter().zip(error_magnitudes.iter()) {
            corrected[pos] = gf256::add(corrected[pos], mag);
        }

        // Verify correction by recomputing syndromes
        let check = self.compute_syndromes(&corrected);
        if !check.iter().all(|&s| s == 0) {
            return Err(DecodeError);
        }

        Ok(corrected[..self.k].to_vec())
    }

    /// Compute syndromes: S_i = r(α^i) for i = 0..2t-1
    fn compute_syndromes(&self, received: &[u8]) -> Vec<u8> {
        let mut syndromes = Vec::with_capacity(self.parity_len);
        for i in 0..self.parity_len {
            let eval_point = gf256::alpha(i);
            // Horner's method, left-to-right (high degree first)
            // r(x) = r[0]·x^{n-1} + r[1]·x^{n-2} + ... + r[n-1]
            let mut val = 0u8;
            for &byte in received {
                val = gf256::add(gf256::mul(val, eval_point), byte);
            }
            syndromes.push(val);
        }
        syndromes
    }

    /// Berlekamp-Massey algorithm to find the error locator polynomial.
    ///
    /// Returns coefficients in ascending degree order: [σ_0, σ_1, ..., σ_v]
    /// where σ_0 = 1 and v is the number of errors.
    fn berlekamp_massey(&self, syndromes: &[u8]) -> Vec<u8> {
        let n = syndromes.len();
        let mut c = vec![1u8]; // Current error locator C(x)
        let mut b = vec![1u8]; // Previous error locator B(x)
        let mut l = 0usize; // Current number of assumed errors
        let mut m = 1usize; // Shift counter
        let mut delta_b = 1u8; // Previous discrepancy

        for r in 0..n {
            // Compute discrepancy: Δ = S_r + σ_1·S_{r-1} + ... + σ_l·S_{r-l}
            let mut delta = syndromes[r];
            for i in 1..=l {
                if i < c.len() {
                    delta = gf256::add(delta, gf256::mul(c[i], syndromes[r - i]));
                }
            }

            if delta == 0 {
                m += 1;
            } else if 2 * l <= r {
                // Increase polynomial degree
                let t_poly = c.clone();
                let factor = gf256::div(delta, delta_b);
                let shift = m;
                while c.len() < b.len() + shift {
                    c.push(0);
                }
                for (i, &bi) in b.iter().enumerate() {
                    c[i + shift] = gf256::add(c[i + shift], gf256::mul(factor, bi));
                }
                l = r + 1 - l;
                b = t_poly;
                delta_b = delta;
                m = 1;
            } else {
                // Update C(x) without increasing degree
                let factor = gf256::div(delta, delta_b);
                let shift = m;
                while c.len() < b.len() + shift {
                    c.push(0);
                }
                for (i, &bi) in b.iter().enumerate() {
                    c[i + shift] = gf256::add(c[i + shift], gf256::mul(factor, bi));
                }
                m += 1;
            }
        }

        c
    }

    /// Chien search: find roots of the error locator polynomial.
    ///
    /// For each array position `i`, the error locator is X = α^{n-1-i}.
    /// σ(X^{-1}) = 0 indicates an error at position `i`.
    fn chien_search(
        &self,
        error_locator: &[u8],
        num_errors: usize,
    ) -> Result<Vec<usize>, DecodeError> {
        let mut positions = Vec::new();

        for i in 0..self.n {
            // Array position i corresponds to power n-1-i.
            // Error locator X = α^{n-1-i}.
            // We check σ(X^{-1}) = σ(α^{i-n+1}).
            // In modular arithmetic: α^{(i + 256 - n) % 255}
            let exp = if self.n - 1 <= i {
                // i >= n-1: power = i - (n-1), always >= 0
                (i - (self.n - 1)) % 255
            } else {
                // i < n-1: power is negative, wrap around
                255 - ((self.n - 1 - i) % 255)
            };
            // Handle the case where exp == 255 (same as 0)
            let exp = exp % 255;
            let x_inv = gf256::alpha(exp);
            let val = gf256::poly_eval(error_locator, x_inv);
            if val == 0 {
                positions.push(i);
            }
        }

        if positions.len() != num_errors {
            return Err(DecodeError);
        }

        Ok(positions)
    }

    /// Forney algorithm: compute error magnitudes given error positions.
    ///
    /// Uses the formula: `e_j = X_j · Ω(X_j^{-1}) / σ'(X_j^{-1})`
    /// where X_j = α^{n-1-pos_j} is the error locator for array position pos_j.
    fn forney_algorithm(
        &self,
        syndromes: &[u8],
        error_locator: &[u8],
        error_positions: &[usize],
    ) -> Result<Vec<u8>, DecodeError> {
        // Error evaluator: Ω(x) = S(x)·σ(x) mod x^{2t}
        let omega = {
            let product = gf256::poly_mul(syndromes, error_locator);
            product
                .into_iter()
                .take(self.parity_len)
                .collect::<Vec<_>>()
        };

        // Formal derivative of σ(x) in GF(2^8):
        // d/dx [σ_k · x^k] = k · σ_k · x^{k-1}
        // In characteristic 2: odd-index coefficients survive, even vanish.
        // σ'(x) = σ_1 + σ_3·x^2 + σ_5·x^4 + ...
        let sigma_prime: Vec<u8> = (0..error_locator.len() - 1)
            .map(|i| {
                if (i + 1) % 2 == 1 {
                    // coefficient of x^i in σ'(x) comes from σ_{i+1}·(i+1)·x^i
                    // (i+1) is odd, so mod 2 = 1
                    error_locator[i + 1]
                } else {
                    0
                }
            })
            .collect();

        let mut magnitudes = Vec::with_capacity(error_positions.len());
        for &pos in error_positions {
            // X = α^{n-1-pos}
            let x_power = self.n - 1 - pos;
            let x = gf256::alpha(x_power % 255);

            // X^{-1} = α^{-(n-1-pos)} computed via gf256::inv
            let x_inv = gf256::inv(x);

            let omega_val = gf256::poly_eval(&omega, x_inv);
            let sigma_prime_val = gf256::poly_eval(&sigma_prime, x_inv);

            if sigma_prime_val == 0 {
                return Err(DecodeError);
            }

            // e = X · Ω(X^{-1}) / σ'(X^{-1})
            let magnitude = gf256::mul(x, gf256::div(omega_val, sigma_prime_val));
            magnitudes.push(magnitude);
        }

        Ok(magnitudes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_no_errors() {
        let rs = ReedSolomon::new(255, 223); // t=16
        let message: Vec<u8> = (0..223).map(|i| (i & 0xFF) as u8).collect();
        let codeword = rs.encode(&message);
        assert_eq!(codeword.len(), 255);

        let decoded = rs.decode(&codeword).expect("decode should succeed");
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_encode_decode_single_error() {
        let rs = ReedSolomon::new(255, 223); // t=16
        let message: Vec<u8> = (0..223).map(|i| (i * 7 & 0xFF) as u8).collect();
        let mut codeword = rs.encode(&message);

        // Introduce 1 error
        codeword[42] ^= 0xFF;

        let decoded = rs.decode(&codeword).expect("decode should succeed");
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_encode_decode_max_errors() {
        let rs = ReedSolomon::new(255, 247); // t=4
        let message: Vec<u8> = (0..247).map(|i| (i * 13 & 0xFF) as u8).collect();
        let mut codeword = rs.encode(&message);

        // Introduce exactly t=4 errors
        codeword[0] ^= 0x01;
        codeword[50] ^= 0x23;
        codeword[100] ^= 0x45;
        codeword[200] ^= 0x67;

        let decoded = rs.decode(&codeword).expect("decode should succeed with t errors");
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_decode_fails_beyond_capacity() {
        let rs = ReedSolomon::new(255, 251); // t=2
        let message: Vec<u8> = (0..251).collect();
        let mut codeword = rs.encode(&message);

        // Introduce t+1=3 errors
        codeword[0] ^= 0xFF;
        codeword[1] ^= 0xFF;
        codeword[2] ^= 0xFF;

        let result = rs.decode(&codeword);
        assert!(result.is_err(), "should fail with too many errors");
    }

    #[test]
    fn test_small_code() {
        let rs = ReedSolomon::new(10, 6); // t=2, small code
        let message = vec![1, 2, 3, 4, 5, 6];
        let codeword = rs.encode(&message);
        assert_eq!(codeword.len(), 10);

        // No errors
        let decoded = rs.decode(&codeword).unwrap();
        assert_eq!(decoded, message);

        // 1 error
        let mut corrupted = codeword.clone();
        corrupted[3] ^= 0xAB;
        let decoded = rs.decode(&corrupted).unwrap();
        assert_eq!(decoded, message);

        // 2 errors (max)
        let mut corrupted = codeword.clone();
        corrupted[0] ^= 0x11;
        corrupted[9] ^= 0x22;
        let decoded = rs.decode(&corrupted).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_generator_polynomial_degree() {
        let rs = ReedSolomon::new(255, 223);
        // Generator should have degree 2t = 32
        assert_eq!(rs.generator.len(), 33); // 33 coefficients for degree 32
        assert_eq!(rs.generator[32], 1); // Leading coefficient is 1 (monic)
    }

    #[test]
    fn test_codeword_is_valid() {
        // A valid codeword should have all-zero syndromes
        let rs = ReedSolomon::new(20, 10);
        let message: Vec<u8> = (0..10).collect();
        let codeword = rs.encode(&message);

        let syndromes = rs.compute_syndromes(&codeword);
        assert!(
            syndromes.iter().all(|&s| s == 0),
            "valid codeword should have zero syndromes"
        );
    }

    #[test]
    fn test_error_in_parity_region() {
        let rs = ReedSolomon::new(20, 10); // t=5
        let message: Vec<u8> = (0..10).collect();
        let mut codeword = rs.encode(&message);

        // Error in parity region
        codeword[15] ^= 0xFF;

        let decoded = rs.decode(&codeword).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_all_positions_single_error() {
        // Verify single-error correction works at every position
        let rs = ReedSolomon::new(15, 11); // t=2
        let message: Vec<u8> = (0..11).collect();
        let codeword = rs.encode(&message);

        for pos in 0..15 {
            let mut corrupted = codeword.clone();
            corrupted[pos] ^= 0x42;
            let decoded = rs.decode(&corrupted).unwrap_or_else(|_| {
                panic!("decode should succeed with single error at position {pos}")
            });
            assert_eq!(decoded, message, "failed at position {pos}");
        }
    }
}
