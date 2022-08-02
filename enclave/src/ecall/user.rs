use crate::attestation::Attested;
use crate::crypto::SharedSecretsDb;
use ecall::keygen::new_sgx_keypair_ext_internal;

use interface::*;
use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxResult;
use std::string::ToString;
use std::vec::Vec;
use unseal::SealInto;

/// Derives shared secrets with all the given KEM pubkeys, and derives a new signing pubkey.
/// Returns sealed secrets, a sealed private key, and a registration message to send to an
/// anytrust node
pub fn new_user(
    anytrust_server_pks: &Vec<ServerPubKeyPackage>,
) -> SgxResult<(SealedSharedSecretDb, SealedSigPrivKey, UserRegistrationBlob)> {
    // 1. validate the input
    let mut kem_pks = vec![];
    for k in anytrust_server_pks {
        if !k.verify_attestation() {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        kem_pks.push(k.kem);
    }

    let role = "user".to_string();

    // 2. generate a SGX protected key. used for both signing and round key derivation
    let (sk, pk) = new_sgx_keypair_ext_internal(&role)?;

    // 3. derive server secrets
    let server_secrets = SharedSecretsDb::derive_shared_secrets(&sk, &kem_pks)?;

    debug!("DH secrets {:?}", server_secrets);

    Ok((server_secrets.seal_into()?, sk.seal_into()?, pk))
}
