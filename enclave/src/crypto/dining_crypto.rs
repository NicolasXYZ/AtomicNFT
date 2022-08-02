use interface::*;
use sgx_types::{sgx_sha256_init, sgx_status_t};

use std::prelude::v1::*;

use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::Sha256;

use super::*;
use sgx_tcrypto::SgxEccHandle;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fmt::Result as FmtResult;
use std::fmt::{Debug, Formatter};

use sgx_rand::{ChaChaRng, Rand, Rng, SeedableRng};

/// A SharedServerSecret is the long-term secret shared between an anytrust server and this use enclave
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffieHellmanSharedSecret([u8; SGX_ECP256_KEY_SIZE]);

impl AsRef<[u8]> for DiffieHellmanSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for DiffieHellmanSharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

use std::cell::RefCell;

/// A ServerSecrets consists of an array of shared secrets established between a user and with a
/// group of any-trust server
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SharedSecretsDb {
    /// round number
    pub round: u32,
    /// a dictionary of keys
    pub db: BTreeMap<SgxProtectedKeyPub, DiffieHellmanSharedSecret>,
}

impl Debug for SharedSecretsDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("SharedSecretsDb")
            .field("round", &self.round)
            .field("db", &self.db)
            .finish()
    }
}

use std::convert::TryFrom;

impl SharedSecretsDb {
    /// Derive shared secrets (using DH). Used at registration time
    pub fn derive_shared_secrets(
        my_sk: &SgxPrivateKey,
        other_pks: &[SgxProtectedKeyPub],
    ) -> SgxResult<Self> {
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open()?;

        let mut server_secrets = BTreeMap::new();

        for server_pk in other_pks.iter() {
            if !ecc_handle.check_point(&server_pk.into())? {
                error!("pk{} not on curve", server_pk);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            }
            let shared_secret =
                match ecc_handle.compute_shared_dhkey(&my_sk.into(), &server_pk.into()) {
                    Ok(ss) => ss,
                    Err(e) => {
                        error!(
                            "error compute_shared_dhkey: err={} sk={} pk={}",
                            e, my_sk, server_pk
                        );
                        return Err(e);
                    }
                };
            server_secrets.insert(
                server_pk.to_owned(),
                DiffieHellmanSharedSecret(shared_secret.s),
            );
        }

        Ok(SharedSecretsDb {
            round: 0,
            db: server_secrets,
        })
    }

    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        compute_anytrust_group_id(&keys)
    }

    /// Return ratcheted keys
    pub fn ratchet(&self) -> SharedSecretsDb {
        let a = self
            .db
            .iter()
            .map(|(&k, v)| {
                let new_key = Sha256::digest(&v.0);
                let mut new_sec = DiffieHellmanSharedSecret::default();
                new_sec.0.copy_from_slice(new_key.as_slice());

                (k, new_sec)
            })
            .collect();

        SharedSecretsDb {
            round: self.round + 1,
            db: a,
        }
    }
}

/// A RoundSecret is an one-time pad for a given round derived from a set of
/// DiffieHellmanSharedSecret, one for each anytrust server.
pub type RoundSecret = DcRoundMessage;

/// Derives a RoundSecret as the XOR of `HKDF(server_secrets[i], round)` for all `i` in `0`...`len(server_secrets)`
pub fn derive_round_secret(
    round: u32,
    server_secrets: &SharedSecretsDb,
) -> CryptoResult<RoundSecret> {
    let mut round_secret = RoundSecret::default();
    for (_, server_secret) in server_secrets.db.iter() {
        let hk = Hkdf::<Sha256>::new(None, server_secret.as_ref());
        // For cryptographic RNG's a seed of 256 bits is recommended, [u8; 32].
        let mut seed = [0u8; 32];

        // info contains round
        let mut info = [0; 32];
        LittleEndian::write_u32(&mut info, round);
        hk.expand(&info, &mut seed)?;

        let mut seed_u32 = [0u32; 8]; // Chacha PRNG in SGX SDK uses u32 as seeds
        byteorder::LittleEndian::read_u32_into(&seed, &mut seed_u32);
        let mut rng = ChaChaRng::from_seed(&seed_u32);
        round_secret.xor_mut(&DcRoundMessage::rand(&mut rng));
    }

    Ok(round_secret)
}

// various functions for computing a.xor(b)
pub trait Xor {
    // xor returns xor(self, other)
    fn xor(&self, other: &Self) -> Self;
    // xor_mut computes and sets self = xor(self, other)
    fn xor_mut(&mut self, other: &Self)
    where
        Self: Sized,
    {
        *self = self.xor(other);
    }
}

impl Xor for DcMessage {
    fn xor(&self, other: &Self) -> Self {
        let mut result = DcMessage::default();
        for i in 0..DC_NET_MESSAGE_LENGTH {
            result.0[i] = self.0[i] ^ other.0[i];
        }

        result
    }
}

impl Xor for DcRoundMessage {
    fn xor(&self, other: &Self) -> Self {
        let mut result = self.clone();

        for i in 0..result.scheduling_msg.len() {
            result.scheduling_msg[i] ^= other.scheduling_msg[i];
        }

        for i in 0..result.aggregated_msg.len() {
            result.aggregated_msg[i].xor_mut(&other.aggregated_msg[i]);
        }

        result
    }
}
