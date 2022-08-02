extern crate sgx_types;

use crate::user_request::EntityId;

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use std::vec::Vec;

use rand_core::RngCore;
use sgx_types::{sgx_ec256_public_t, SGX_ECP256_KEY_SIZE};

// A wrapper around sgx_ec256_public_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct SgxProtectedKeyPub {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE],
}

impl Debug for SgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", hex::encode(&self.gx), hex::encode(&self.gy))
    }
}

impl Display for SgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({}, {})", hex::encode(self.gx), hex::encode(self.gy))
    }
}

impl From<sgx_ec256_public_t> for SgxProtectedKeyPub {
    fn from(sgx_ec_pubkey: sgx_ec256_public_t) -> Self {
        return Self {
            gx: sgx_ec_pubkey.gx,
            gy: sgx_ec_pubkey.gy,
        };
    }
}

impl Into<sgx_ec256_public_t> for SgxProtectedKeyPub {
    fn into(self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }
}

impl Into<sgx_ec256_public_t> for &SgxProtectedKeyPub {
    fn into(self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }
}

impl SgxProtectedKeyPub {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        EntityId::from(self)
    }

    // TODO: Make this generate valid pubkeys
    // Generates a random and NOT VALID pubkey
    pub fn rand_invalid_placeholder<R: RngCore>(rng: &mut R) -> Self {
        let mut gx = [0u8; SGX_ECP256_KEY_SIZE];
        let mut gy = [0u8; SGX_ECP256_KEY_SIZE];

        rng.fill_bytes(&mut gx);
        rng.fill_bytes(&mut gy);

        return Self { gx, gy };
    }
}

/// KemPubKey and SgxSigningPubKey are just aliases to SgxProtectedKeyPub
pub type KemPubKey = SgxProtectedKeyPub;
pub type SgxSigningPubKey = SgxProtectedKeyPub;

/// AttestedPublicKey is pk + attestation
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttestedPublicKey {
    pub pk: SgxProtectedKeyPub,
    pub role: std::string::String,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub tee_linkable_attestation: std::vec::Vec<u8>, // binds this key to an enclave
}

impl Debug for AttestedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SgxProtectedKeyPair")
            .field("pk", &self.pk)
            .field("role", &self.role)
            .field(
                "tee_linkable_attestation",
                &hex::encode(&self.tee_linkable_attestation),
            )
            .finish()
    }
}

/// An enclave-generated private signing key
// #[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
// #[derive(Clone, Serialize, Deserialize)]
// pub struct SealedKeyPair {
//     pub sealed_sk: Vec<u8>,
//     pub attested_pk: AttestedPublicKey,
// }
//
// /// We implement Default for all Sealed* types
// /// Invariant: default values are "ready to use" in ecall.
// /// That usually means we have allocated enough memory for the enclave to write to.
// impl Default for SealedKeyPair {
//     fn default() -> Self {
//         SealedKeyPair {
//             sealed_sk: vec![0u8; 1024], // 1024 seems enough
//             attested_pk: AttestedPublicKey::default(),
//         }
//     }
// }
//
// impl Debug for SealedKeyPair {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("SealedKey")
//             .field("sealed_sk", &format!("{} bytes", self.sealed_sk.len()))
//             .field("pk", &self.attested_pk)
//             .finish()
//     }
// }

/// Contains a server's signing and KEM pubkeys
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerPubKeyPackage {
    pub sig: SgxSigningPubKey,
    pub kem: KemPubKey,
    /// One attestation proving the association of the two keys
    pub attestation: Vec<u8>,
}
