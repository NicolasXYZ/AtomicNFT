use interface::{KemPubKey, SgxProtectedKeyPub};
use sgx_rand::{Rand, Rng};
use sgx_types::{sgx_ec256_private_t, sgx_status_t, SGX_ECP256_KEY_SIZE};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};

// A wrapper around sgx_ec256_private_t
#[derive(Copy, Clone, Default, Serialize, Deserialize)]
pub struct SgxPrivateKey {
    pub r: [u8; SGX_ECP256_KEY_SIZE],
}

impl Rand for SgxPrivateKey {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut r = [0 as u8; SGX_ECP256_KEY_SIZE];
        rng.fill_bytes(&mut r);

        SgxPrivateKey { r }
    }
}

impl Debug for SgxPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SK")
            .field("r", &hex::encode(&self.r))
            .finish()
    }
}

impl Display for SgxPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::write!(f, "{}", hex::encode(self.r))
    }
}

impl From<sgx_ec256_private_t> for SgxPrivateKey {
    fn from(sgx_prv_key: sgx_ec256_private_t) -> Self {
        return Self { r: sgx_prv_key.r };
    }
}

impl Into<sgx_ec256_private_t> for SgxPrivateKey {
    fn into(self) -> sgx_ec256_private_t {
        return sgx_ec256_private_t { r: self.r };
    }
}

impl Into<sgx_ec256_private_t> for &SgxPrivateKey {
    fn into(self) -> sgx_ec256_private_t {
        return sgx_ec256_private_t { r: self.r };
    }
}

impl AsRef<[u8]> for &SgxPrivateKey {
    fn as_ref(&self) -> &[u8] {
        return &self.r;
    }
}

impl TryFrom<&SgxPrivateKey> for SgxProtectedKeyPub {
    type Error = sgx_status_t;

    fn try_from(prv_key: &KemPrvKey) -> Result<Self, Self::Error> {
        sgx_tcrypto::rsgx_ecc256_pub_from_priv(&prv_key.into()).map(KemPubKey::from)
    }
}

// KemPrvKey and SgxSigningKey are aliases to SgxProtectedPrivateKey
pub type KemPrvKey = SgxPrivateKey;
pub type SgxSigningKey = SgxPrivateKey;
