// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G1Affine, G1Projective, Scalar};
use group::{Curve, GroupEncoding};

use crate::error::{CoconutError, Result};
use crate::proofs::ProofCmCs;
use crate::scheme::setup::Parameters;
use crate::scheme::BlindedSignature;
use crate::scheme::SecretKey;
use crate::Attribute;
/// Creates a Coconut Signature under a given secret key on a set of public attributes only.
#[cfg(test)]
use crate::Signature;
// TODO: possibly completely remove those two functions.
// They only exist to have a simpler and smaller code snippets to test
// basic functionalities.
use crate::traits::{Base58, Bytable};
use crate::utils::{hash_g1, try_deserialize_g1_projective};

// TODO NAMING: double check this one
// Lambda
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct BlindSignRequest {
    // cm
    commitment: G1Projective,
    // h
    commitment_hash: G1Projective,
    // c
    private_attributes_commitments: Vec<G1Projective>,
    // pi_s
    pi_s: ProofCmCs,
}

impl TryFrom<&[u8]> for BlindSignRequest {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<BlindSignRequest> {
        if bytes.len() < 48 + 48 + 8 + 48 {
            return Err(CoconutError::DeserializationMinLength {
                min: 48 + 48 + 8 + 48,
                actual: bytes.len(),
            });
        }

        let mut j = 0;
        let commitment_bytes_len = 48;
        let commitment_hash_bytes_len = 48;

        let cm_bytes = bytes[..j + commitment_bytes_len].try_into().unwrap();
        let commitment = try_deserialize_g1_projective(
            &cm_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize compressed commitment".to_string(),
            ),
        )?;
        j += commitment_bytes_len;

        let cm_hash_bytes = bytes[j..j + commitment_hash_bytes_len].try_into().unwrap();
        let commitment_hash = try_deserialize_g1_projective(
            &cm_hash_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize compressed commitment hash".to_string(),
            ),
        )?;
        j += commitment_hash_bytes_len;

        let c_len = u64::from_le_bytes(bytes[j..j + 8].try_into().unwrap());
        j += 8;
        if bytes[j..].len() < c_len as usize * 48 {
            return Err(CoconutError::DeserializationMinLength {
                min: c_len as usize * 48,
                actual: bytes[56..].len(),
            });
        }

        let mut private_attributes_commitments = Vec::with_capacity(c_len as usize);
        for i in 0..c_len as usize {
            let start = j + i * 48;
            let end = start + 48;

            let private_attributes_commitment_bytes = bytes[start..end].try_into().unwrap();
            let private_attributes_commitment = try_deserialize_g1_projective(
                &private_attributes_commitment_bytes,
                CoconutError::Deserialization(
                    "Failed to deserialize compressed commitment".to_string(),
                ),
            )?;

            private_attributes_commitments.push(private_attributes_commitment)
        }

        let pi_s = ProofCmCs::from_bytes(&bytes[j + c_len as usize * 48..])?;

        Ok(BlindSignRequest {
            commitment,
            commitment_hash,
            private_attributes_commitments,
            pi_s,
        })
    }
}

impl Bytable for BlindSignRequest {
    fn to_byte_vec(&self) -> Vec<u8> {
        let cm_bytes = self.commitment.to_affine().to_compressed();
        let cm_hash_bytes = self.commitment_hash.to_affine().to_compressed();
        let c_len = self.private_attributes_commitments.len() as u64;
        let proof_bytes = self.pi_s.to_bytes();

        let mut bytes = Vec::with_capacity(48 + 48 + 8 + c_len as usize * 48 + proof_bytes.len());

        bytes.extend_from_slice(&cm_bytes);
        bytes.extend_from_slice(&cm_hash_bytes);
        bytes.extend_from_slice(&c_len.to_le_bytes());
        for c in &self.private_attributes_commitments {
            bytes.extend_from_slice(&c.to_affine().to_compressed());
        }

        bytes.extend_from_slice(&proof_bytes);

        bytes
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        BlindSignRequest::from_bytes(slice)
    }
}

impl Base58 for BlindSignRequest {}

impl BlindSignRequest {
    fn verify_proof(&self, params: &Parameters, public_attributes: &[Attribute]) -> bool {
        self.pi_s.verify(
            params,
            &self.commitment,
            &self.private_attributes_commitments,
            public_attributes,
        )
    }

    pub fn get_commitment_hash(&self) -> G1Projective {
        self.commitment_hash
    }

    pub fn get_private_attributes_pedersen_commitments(&self) -> Vec<G1Projective> {
        self.private_attributes_commitments.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_byte_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BlindSignRequest> {
        BlindSignRequest::try_from(bytes)
    }
}

pub fn compute_attributes_commitment(
    params: &Parameters,
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
    hs: &[G1Affine],
) -> (Scalar, G1Projective) {
    let commitment_opening = params.random_scalar();

    // Produces h0 ^ m0 * h1^m1 * .... * hn^mn
    // where m0, m1, ...., mn are attributes
    let attr_cm = private_attributes
        .iter()
        .chain(public_attributes.iter())
        .zip(hs)
        .map(|(&m, h)| h * m)
        .sum::<G1Projective>();

    // Produces g1^r * h0 ^ m0 * h1^m1 * .... * hn^mn
    let commitment = params.gen1() * commitment_opening + attr_cm;
    (commitment_opening, commitment)
}

pub fn compute_pedersen_commitments_for_private_attributes(
    params: &Parameters,
    private_attributes: &[Attribute],
    h: &G1Projective,
) -> (Vec<Scalar>, Vec<G1Projective>) {
    // Generate openings for Pedersen commitment for each private attribute
    let commitments_openings = params.n_random_scalars(private_attributes.len());

    // Compute Pedersen commitment for each private attribute
    let pedersen_commitments = commitments_openings
        .iter()
        .zip(private_attributes.iter())
        .map(|(o_j, m_j)| params.gen1() * o_j + h * m_j)
        .collect::<Vec<_>>();

    (commitments_openings, pedersen_commitments)
}

pub fn compute_commitment_hash(commitment: G1Projective) -> G1Projective {
    hash_g1(commitment.to_bytes())
}

/// Builds cryptographic material required for blind sign.
pub fn prepare_blind_sign(
    params: &Parameters,
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
) -> Result<(Vec<Scalar>, BlindSignRequest)> {
    if private_attributes.is_empty() {
        return Err(CoconutError::Issuance(
            "Tried to prepare blind sign request for an empty set of private attributes"
                .to_string(),
        ));
    }

    let hs = params.gen_hs();
    if private_attributes.len() + public_attributes.len() > hs.len() {
        return Err(CoconutError::IssuanceMaxAttributes {
            max: hs.len(),
            requested: private_attributes.len() + public_attributes.len(),
        });
    }

    let (commitment_opening, commitment) =
        compute_attributes_commitment(params, private_attributes, public_attributes, hs);

    // Compute the challenge as the commitment hash
    let commitment_hash = compute_commitment_hash(commitment);

    let (pedersen_commitments_openings, pedersen_commitments) =
        compute_pedersen_commitments_for_private_attributes(
            params,
            private_attributes,
            &commitment_hash,
        );

    let pi_s = ProofCmCs::construct(
        params,
        &commitment,
        &commitment_opening,
        &pedersen_commitments,
        &pedersen_commitments_openings,
        private_attributes,
    );

    Ok((
        pedersen_commitments_openings,
        BlindSignRequest {
            commitment,
            commitment_hash,
            private_attributes_commitments: pedersen_commitments,
            pi_s,
        },
    ))
}

pub fn blind_sign(
    params: &Parameters,
    signing_secret_key: &SecretKey,
    blind_sign_request: &BlindSignRequest,
    public_attributes: &[Attribute],
) -> Result<BlindedSignature> {
    let num_private = blind_sign_request.private_attributes_commitments.len();
    let hs = params.gen_hs();

    if num_private + public_attributes.len() > hs.len() {
        return Err(CoconutError::IssuanceMaxAttributes {
            max: hs.len(),
            requested: num_private + public_attributes.len(),
        });
    }

    // Verify the commitment hash
    let h = hash_g1(blind_sign_request.commitment.to_bytes());
    if !(h == blind_sign_request.commitment_hash) {
        return Err(CoconutError::Issuance(
            "Failed to verify the commitment hash".to_string(),
        ));
    }

    // Verify the ZK proof
    if !blind_sign_request.verify_proof(params, public_attributes) {
        return Err(CoconutError::Issuance(
            "Failed to verify the proof of knowledge".to_string(),
        ));
    }

    // in python implementation there are n^2 G1 multiplications, let's do it with a single one instead.
    // i.e. compute h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n]) directly (where m is number of PRIVATE attributes)
    // rather than ((h ^ pub_m[0]) ^ y[m + 1] , (h ^ pub_m[1]) ^ y[m + 2] , ...).sum() separately
    let signed_public = h * public_attributes
        .iter()
        .zip(signing_secret_key.ys.iter().skip(num_private))
        .map(|(attr, yi)| attr * yi)
        .sum::<Scalar>();

    // h ^ x + c[0] ^ y[0] + ... c[m] ^ y[m] + h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n])
    let sig = blind_sign_request
        .private_attributes_commitments
        .iter()
        .zip(signing_secret_key.ys.iter())
        .map(|(c, yi)| c * yi)
        .chain(std::iter::once(h * signing_secret_key.x))
        .chain(std::iter::once(signed_public))
        .sum();

    Ok(BlindedSignature(h, sig))
}

#[cfg(test)]
pub fn sign(
    params: &mut Parameters,
    secret_key: &SecretKey,
    public_attributes: &[Attribute],
) -> Result<Signature> {
    if public_attributes.len() > secret_key.ys.len() {
        return Err(CoconutError::IssuanceMaxAttributes {
            max: secret_key.ys.len(),
            requested: public_attributes.len(),
        });
    }

    // TODO: why in the python implementation this hash onto the curve is present
    // while it's not used in the paper? the paper uses random exponent instead.
    // (the python implementation hashes string representation of all attributes onto the curve,
    // but I think the same can be achieved by just summing the attributes thus avoiding the unnecessary
    // transformation. If I'm wrong, please correct me.)
    let attributes_sum = public_attributes.iter().sum::<Scalar>();
    let h = hash_g1((params.gen1() * attributes_sum).to_bytes());

    // x + m0 * y0 + m1 * y1 + ... mn * yn
    let exponent = secret_key.x
        + public_attributes
            .iter()
            .zip(secret_key.ys.iter())
            .map(|(m_i, y_i)| m_i * y_i)
            .sum::<Scalar>();

    let sig2 = h * exponent;
    Ok(Signature(h, sig2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_sign_request_bytes_roundtrip() {
        // 0 public and 1 private attribute
        let params = Parameters::new(1).unwrap();
        let private_attributes = params.n_random_scalars(1);
        let public_attributes = params.n_random_scalars(0);

        let (_commitments_openings, lambda) =
            prepare_blind_sign(&params, &private_attributes, &public_attributes).unwrap();

        let bytes = lambda.to_bytes();
        assert_eq!(
            BlindSignRequest::try_from(bytes.as_slice()).unwrap(),
            lambda
        );

        // 2 public and 2 private attributes
        let params = Parameters::new(4).unwrap();
        let private_attributes = params.n_random_scalars(2);
        let public_attributes = params.n_random_scalars(2);

        let (_commitments_openings, lambda) =
            prepare_blind_sign(&params, &private_attributes, &public_attributes).unwrap();

        let bytes = lambda.to_bytes();
        assert_eq!(
            BlindSignRequest::try_from(bytes.as_slice()).unwrap(),
            lambda
        );
    }
}
