mod gf256;

use gf256::GF256;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("shares must be between 2 and 255")]
    InvalidShareCount,
    #[error("threshold must be between 2 and 255")]
    InvalidThreshold,
    #[error("shares cannot be less than threshold")]
    SharesLessThanThreshold,
    #[error("secret cannot be empty")]
    EmptySecret,
    #[error("shares must contain unique values")]
    DuplicateShares,
    #[error("all shares must have the same length")]
    InconsistentShareLength,
    #[error("share count mismatch")]
    ShareCountMismatch,
    #[error("invalid share identifier")]
    InvalidShareIdentifier,
}

/// Share represents a single share from the Shamir Secret Sharing scheme
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub id: u8,
    pub data: Vec<u8>,
}

/// Split a secret into n shares, requiring k shares to reconstruct
pub fn split(
    secret: &[u8], 
    shares: usize, 
    threshold: usize,
    rng_seed: Option<[u8; 32]>,
) -> Result<Vec<Share>, ShamirError> {
    // Validate inputs
    if shares < 2 || shares > 255 {
        return Err(ShamirError::InvalidShareCount);
    }
    if threshold < 2 || threshold > 255 {
        return Err(ShamirError::InvalidThreshold);
    }
    if shares < threshold {
        return Err(ShamirError::SharesLessThanThreshold);
    }
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }

    // Create deterministic RNG if seed is provided, otherwise use system RNG
    let mut rng = match rng_seed {
        Some(seed) => ChaCha20Rng::from_seed(seed),
        None => ChaCha20Rng::from_entropy(),
    };

    // Generate unique x-coordinates for each share
    let mut x_coords: Vec<u8> = (1..=shares as u8).collect();
    for i in 0..x_coords.len() {
        let j = rng.gen_range(0..x_coords.len());
        x_coords.swap(i, j);
    }

    let degree = threshold - 1;
    let mut shares_result = Vec::with_capacity(shares);
    
    // Process each byte of the secret
    for byte in secret {
        // Generate random coefficients for polynomial
        let mut coefficients = vec![*byte]; // First coefficient is the secret byte
        for _ in 0..degree {
            coefficients.push(rng.gen());
        }

        // Evaluate polynomial for each share's x-coordinate
        for (i, &x) in x_coords.iter().enumerate() {
            if i >= shares_result.len() {
                shares_result.push(Share {
                    id: x,
                    data: Vec::with_capacity(secret.len()),
                });
            }
            
            // Evaluate polynomial at point x
            let mut result = GF256::new(0);
            let mut power = GF256::new(1);
            
            for &coeff in &coefficients {
                result = result + (GF256::new(coeff) * power);
                power = power * GF256::new(x);
            }
            
            shares_result[i].data.push(result.value());
        }

        // Zeroize coefficients after use
        coefficients.zeroize();
    }

    Ok(shares_result)
}

/// Combine shares to recover the original secret
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    if shares.len() < 2 {
        return Err(ShamirError::InvalidShareCount);
    }
    
    // Check that all shares have the same length
    let first_len = shares[0].data.len();
    if shares.iter().any(|s| s.data.len() != first_len) {
        return Err(ShamirError::InconsistentShareLength);
    }
    
    // Ensure all share IDs are unique
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        if !seen.insert(share.id) {
            return Err(ShamirError::DuplicateShares);
        }
        if share.id == 0 {
            return Err(ShamirError::InvalidShareIdentifier);
        }
    }

    let mut result = Vec::with_capacity(first_len);
    
    // For each byte position across all shares
    for byte_idx in 0..first_len {
        let mut value = GF256::new(0);
        
        // Lagrange interpolation
        for (i, share_i) in shares.iter().enumerate() {
            let mut term = GF256::new(1);
            let x_i = GF256::new(share_i.id);
            
            for (j, share_j) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                
                let x_j = GF256::new(share_j.id);
                let numerator = GF256::new(0) - x_j;
                let denominator = x_i - x_j;
                term = term * (numerator / denominator);
            }
            
            term = term * GF256::new(share_i.data[byte_idx]);
            value = value + term;
        }
        
        result.push(value.value());
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_split_and_combine() {
        let secret = b"Secret seed phrase for testing";
        
        // Split into 5 shares, require 3 to reconstruct
        let shares = split(secret, 5, 3, None).unwrap();
        assert_eq!(shares.len(), 5);
        
        // Check that all shares have correct length
        for share in &shares {
            assert_eq!(share.data.len(), secret.len());
        }
        
        // Combine all shares
        let recovered = combine(&shares).unwrap();
        assert_eq!(recovered, secret);
        
        // Combine only threshold (3) shares
        let partial_shares = vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
        ];
        
        let recovered_partial = combine(&partial_shares).unwrap();
        assert_eq!(recovered_partial, secret);
    }
    
    #[test]
    fn test_invalid_parameters() {
        let secret = b"Test secret";
        
        // Shares less than 2
        assert!(split(secret, 1, 1, None).is_err());
        
        // Threshold less than 2
        assert!(split(secret, 3, 1, None).is_err());
        
        // Shares less than threshold
        assert!(split(secret, 3, 4, None).is_err());
        
        // Empty secret
        assert!(split(&[], 3, 2, None).is_err());
    }
    
    #[test]
    fn test_deterministic_generation() {
        let secret = b"Deterministic test";
        let seed = [42u8; 32];
        
        let shares1 = split(secret, 3, 2, Some(seed)).unwrap();
        let shares2 = split(secret, 3, 2, Some(seed)).unwrap();
        
        // Shares should be identical with the same seed
        assert_eq!(shares1, shares2);
    }
    
    #[test]
    fn test_insufficient_shares() {
        let secret = b"Need more shares";
        let shares = split(secret, 5, 3, None).unwrap();
        
        // Try to combine with fewer than threshold
        let insufficient = vec![shares[0].clone(), shares[1].clone()];
        
        // The math will produce an incorrect result, but it won't error
        let recovered = combine(&insufficient).unwrap();
        assert_ne!(recovered, secret);
    }
}