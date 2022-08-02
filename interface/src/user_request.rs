use std::collections::BTreeSet;
use std::prelude::v1::*;

use crate::{ecall_interface_types::*, params::*, sgx_protected_keys::*};

use sha2::{Digest, Sha256};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

big_array! { BigArray; }

// a wrapper around RawMessage so that we can impl traits
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DcMessage(#[serde(with = "BigArray")] pub [u8; DC_NET_MESSAGE_LENGTH]);

impl Default for DcMessage {
    fn default() -> DcMessage {
        DcMessage([0u8; DC_NET_MESSAGE_LENGTH])
    }
}

#[cfg(feature = "trusted")]
use sgx_rand::{Rand, Rng};

#[cfg(feature = "trusted")]
impl Rand for DcMessage {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut r = DcMessage::default();
        rng.fill_bytes(&mut r.0);

        r
    }
}

impl std::cmp::PartialEq for DcMessage {
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).all(|(x, y)| x == y)
    }
}

impl Debug for DcMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Try interpreting as UTF-8. If it fails, write out the base64
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            f.write_str(&s)
        } else {
            f.write_str(&base64::encode(&self.0))
        }
    }
}

impl From<[u8; DC_NET_MESSAGE_LENGTH]> for DcMessage {
    fn from(raw: [u8; DC_NET_MESSAGE_LENGTH]) -> Self {
        DcMessage(raw)
    }
}

impl AsRef<[u8]> for DcMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; DC_NET_MESSAGE_LENGTH]> for DcMessage {
    fn as_ref(&self) -> &[u8; DC_NET_MESSAGE_LENGTH] {
        &self.0
    }
}

/// we store footprints in u32s (enclave/ecall/submit.rs)
pub type Footprint = u32;

/// What's broadcast through the channel
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct DcRoundMessage {
    #[serde(with = "BigArray")]
    pub scheduling_msg: [Footprint; FOOTPRINT_N_SLOTS],
    #[serde(with = "BigArray")]
    pub aggregated_msg: [DcMessage; DC_NET_N_SLOTS],
}

/// Used to generate round secrets
#[cfg(feature = "trusted")]
impl Rand for DcRoundMessage {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut m = DcRoundMessage::default();

        for i in 0..m.scheduling_msg.len() {
            m.scheduling_msg[i] = rng.next_u32();
        }

        for i in 0..m.aggregated_msg.len() {
            m.aggregated_msg[i] = DcMessage::rand(rng);
        }

        m
    }
}

impl Default for DcRoundMessage {
    fn default() -> Self {
        DcRoundMessage {
            scheduling_msg: [0; FOOTPRINT_N_SLOTS],
            aggregated_msg: [DcMessage::default(); DC_NET_N_SLOTS],
        }
    }
}

impl PartialEq for DcRoundMessage {
    fn eq(&self, other: &Self) -> bool {
        self.aggregated_msg == other.aggregated_msg && self.scheduling_msg == other.scheduling_msg
    }
}

impl Debug for DcRoundMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("DcRoundMessage")
            .field("scheduling_msg", &self.scheduling_msg)
            .field("aggregated_msg", &self.aggregated_msg)
            .finish()
    }
}

impl DcRoundMessage {
    /// used by signature
    pub fn digest(&self) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        for i in self.scheduling_msg.iter() {
            b.extend(&i.to_le_bytes())
        }

        for i in self.aggregated_msg.iter() {
            b.extend(&i.0)
        }

        b
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityId(pub [u8; USER_ID_LENGTH]);

impl Display for EntityId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(self.0))
    }
}

impl Debug for EntityId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(self.0))
    }
}

impl AsRef<[u8]> for EntityId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; USER_ID_LENGTH]> for EntityId {
    fn from(raw: [u8; USER_ID_LENGTH]) -> Self {
        EntityId(raw)
    }
}

impl From<&SgxProtectedKeyPub> for EntityId {
    fn from(pk: &SgxProtectedKeyPub) -> Self {
        let mut hasher = Sha256::new();
        hasher.update("anytrust_group_id");
        hasher.update(pk.gx);
        hasher.update(pk.gy);

        let digest = hasher.finalize();

        let mut id = EntityId::default();
        id.0.copy_from_slice(&digest);
        id
    }
}

impl From<&AttestedPublicKey> for EntityId {
    fn from(pk: &AttestedPublicKey) -> Self {
        EntityId::from(&pk.pk)
    }
}

impl From<&ServerPubKeyPackage> for EntityId {
    // server's entity id is computed from the signing key
    fn from(spk: &ServerPubKeyPackage) -> Self {
        EntityId::from(&spk.sig)
    }
}

/// Computes a group ID given a list of entity IDs
pub fn compute_group_id(ids: &BTreeSet<EntityId>) -> EntityId {
    // The group ID of a set of entities is the hash of their IDs, concatenated in ascending order.
    // There's also the context str of "grp" prepended.
    let mut hasher = Sha256::new();
    hasher.update(b"grp");
    for id in ids {
        hasher.update(&id.0);
    }
    let digest = hasher.finalize();

    let mut id = EntityId::default();
    id.0.copy_from_slice(&digest);
    id
}

/// An anytrust_group_id is computed from sig keys
pub fn compute_anytrust_group_id(keys: &[SgxSigningPubKey]) -> EntityId {
    compute_group_id(&keys.iter().map(|k| EntityId::from(k)).collect())
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSubmissionReq {
    pub user_id: EntityId,
    pub anytrust_group_id: EntityId,
    pub round: u32,
    pub msg: DcMessage,
    /// output of previous round signed by one or more anytrust server
    pub prev_round_output: RoundOutput,
    /// A map from server KEM public key to sealed shared secret
    pub shared_secrets: SealedSharedSecretDb,
    /// A list of server public keys (can be verified using the included attestation)
    pub server_pks: Vec<ServerPubKeyPackage>,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserReservationReq {
    pub user_id: EntityId,
    pub anytrust_group_id: EntityId,
    pub round: u32,
    /// A map from server public key to sealed shared secret
    pub shared_secrets: SealedSharedSecretDb,
    /// A list of server public keys (can be verified using the included attestation)
    pub server_pks: Vec<ServerPubKeyPackage>,
}
