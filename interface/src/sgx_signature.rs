use crate::SgxSigningPubKey;
use sgx_types::{sgx_ec256_signature_t, SGX_NISTP_ECP256_KEY_SIZE};
use std::fmt::{Debug, Formatter, Result as FmtResult};

// A wrapper around sgx_ec256_signature_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize)]
pub struct SgxSignature {
    pub x: [u32; SGX_NISTP_ECP256_KEY_SIZE],
    pub y: [u32; SGX_NISTP_ECP256_KEY_SIZE],
}

impl Into<sgx_ec256_signature_t> for SgxSignature {
    fn into(self) -> sgx_ec256_signature_t {
        return sgx_ec256_signature_t {
            x: self.x,
            y: self.y,
        };
    }
}

impl From<sgx_ec256_signature_t> for SgxSignature {
    fn from(sig: sgx_ec256_signature_t) -> Self {
        Self { x: sig.x, y: sig.y }
    }
}

impl Debug for SgxSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let hex_u32_vec = |array: &[u32]| {
            let x = std::vec::Vec::<u8>::with_capacity(4 * self.x.len());
            let x = array.iter().fold(x, |mut acc, elem| {
                acc.extend(&elem.to_be_bytes());
                acc
            });
            hex::encode(&x)
        };

        f.write_str(&std::format!(
            "({}, {})",
            &hex_u32_vec(&self.x),
            &hex_u32_vec(&self.y)
        ))
    }
}

/// Used by users (in request) and servers (in round outputs)
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub pk: SgxSigningPubKey,
    pub sig: SgxSignature,
}
