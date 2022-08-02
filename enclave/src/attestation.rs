/// everything about verifying attestations
use interface::{AttestedPublicKey, ServerPubKeyPackage};

pub trait Attested {
    fn verify_attestation(&self) -> bool;
}

impl Attested for ServerPubKeyPackage {
    fn verify_attestation(&self) -> bool {
        warn!("TODO: actually check attestation for ServerPubKeyPackage");
        true
    }
}

impl Attested for AttestedPublicKey {
    fn verify_attestation(&self) -> bool {
        warn!("TODO: actually check attestation for ServerPubKeyPackage");
        true
    }
}
