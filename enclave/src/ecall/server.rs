use crate::attestation::Attested;
use crate::crypto::Xor;
use crate::crypto::{
    derive_round_secret, KemPrvKey, SgxPrivateKey, SharedSecretsDb, SignMutable, Signable,
};
use crate::messages_types;
use crate::unseal::{MarshallAs, UnmarshalledAs, UnsealableInto};
use ecall::keygen::new_sgx_keypair_ext_internal;
use interface::*;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxResult;
use std::borrow::ToOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::string::ToString;
use std::{debug, vec};

/// This file implements ecalls used by an anytrust server

/// Create two keys for a new server
pub fn new_server(
    _: &(),
) -> SgxResult<(SealedSigPrivKey, SealedKemPrivKey, ServerRegistrationBlob)> {
    let sig_key = new_sgx_keypair_ext_internal(&"server_sig".to_string())?;
    let kem_key = new_sgx_keypair_ext_internal(&"server_kem".to_string())?;

    let reg = ServerRegistrationBlob {
        sig: sig_key.1.pk,
        kem: kem_key.1.pk,
        attestation: vec![0],
    };

    Ok((sig_key.0.seal_into()?, kem_key.0.seal_into()?, reg))
}

/// Verifies and adds the given user registration blob to the database of pubkeys and
/// shared secrets
/// TODO: the second input is currently not used. We always build a new SealedSharedSecretDb from SignedPubKeyDb.
pub fn recv_user_registration(
    input: &(
        SignedPubKeyDb,
        SealedSharedSecretDb,
        SealedKemPrivKey,
        UserRegistrationBlob,
    ),
) -> SgxResult<(SignedPubKeyDb, SealedSharedSecretDb)> {
    let mut pk_db = input.0.clone();

    // verify user key
    let user_pk = &input.3;
    if !user_pk.verify_attestation() {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // add user key to pubkey db
    pk_db
        .users
        .insert(EntityId::from(&user_pk.pk), user_pk.clone());

    // Derive secrets
    let my_kem_sk: SgxPrivateKey = input.2.unseal_into()?;
    let mut others_kem_pks = vec![];
    for (_, k) in pk_db.users.iter() {
        others_kem_pks.push(k.pk);
    }

    let shared_secrets = SharedSecretsDb::derive_shared_secrets(&my_kem_sk, &others_kem_pks)?;

    debug!("shared_secrets {:?}", shared_secrets);

    Ok((pk_db, shared_secrets.seal_into()?))
}

pub fn recv_aggregator_registration(
    input: &(SignedPubKeyDb, AggRegistrationBlob),
) -> SgxResult<SignedPubKeyDb> {
    let (pk_db, attested_pk) = input;
    let mut pk_db = pk_db.clone();

    // verify user key
    let attested_pk = &attested_pk.0;
    warn!("skipping verifying attestation for now");

    // add user key to pubkey db
    pk_db
        .aggregators
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned());

    Ok(pk_db)
}

pub fn recv_server_registration(
    input: &(SignedPubKeyDb, ServerRegistrationBlob),
) -> SgxResult<SignedPubKeyDb> {
    let (pk_db, attested_pk) = input;
    let mut pk_db = pk_db.clone();

    if !attested_pk.verify_attestation() {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // add server's key package to pubkey db
    pk_db
        .servers
        .insert(EntityId::from(&attested_pk.kem), attested_pk.clone());

    Ok(pk_db)
}

use std::iter::FromIterator;

/// XORs the shared secrets into the given aggregate. Returns the server's share of the
/// unblinded aggregate as well as the ratcheted shared secrets.
///
/// This is invoked by the root anytrust server.
pub fn unblind_aggregate(
    input: &(RoundSubmissionBlob, SealedSigPrivKey, SealedSharedSecretDb),
) -> SgxResult<(UnblindedAggregateShareBlob, SealedSharedSecretDb)> {
    let round_msg = input.0.unmarshal()?;
    let sig_key = input.1.unseal_into()?;
    let shared_secrets = input.2.unseal_into()?;

    if round_msg.round != shared_secrets.round {
        error!(
            "wrong round. round_msg.round {} != shared_secrets.round {}",
            round_msg.round, shared_secrets.round
        );
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let user_ids_in_secret_db = BTreeSet::from_iter(shared_secrets.db.keys().map(EntityId::from));
    if !(round_msg.user_ids == user_ids_in_secret_db
        || round_msg.user_ids.is_subset(&user_ids_in_secret_db))
    {
        error!("submission.user_ids is not a subset of user_ids_in_secret_db. user_ids_in_submission = {:?}, user_ids_in_secret_db= {:?}",
        round_msg.user_ids,
        user_ids_in_secret_db);
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let round_secret = derive_round_secret(round_msg.round, &shared_secrets).map_err(|_| {
        error!("crypto error");
        SGX_ERROR_INVALID_PARAMETER
    })?;

    // XOR server's secrets
    // round_msg.aggregated_msg.xor_mut(&round_secret);

    let mut unblined_agg = messages_types::UnblindedAggregateShare {
        encrypted_msg: round_msg,
        key_share: round_secret,
        sig: Default::default(),
        pk: Default::default(),
    };

    // sign
    unblined_agg.sign_mut(&sig_key)?;

    Ok((
        unblined_agg.marshal()?,
        shared_secrets.ratchet().seal_into()?,
    ))
}

use crypto::MultiSignable;
use std::vec::Vec;
use unseal::SealInto;

pub fn derive_round_output(
    input: &(SealedSigPrivKey, Vec<UnblindedAggregateShareBlob>),
) -> SgxResult<RoundOutput> {
    let (signing_sk, shares) = input;
    if shares.is_empty() {
        error!("empty shares array");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // TODO: check all shares are for the same around & same message

    // Xor of all server secrets
    let mut final_msg = DcRoundMessage::default();

    // We require all s in shares should have the same aggregated_msg
    let first_msg = shares[0].unmarshal()?;
    let final_aggregation = first_msg.encrypted_msg.aggregated_msg;
    let round = first_msg.encrypted_msg.round;

    for s in shares.iter() {
        let share = s.unmarshal()?;
        if share.encrypted_msg.aggregated_msg != final_aggregation {
            error!("share {:?} has a different final agg", share);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        final_msg.xor_mut(&share.key_share);
    }

    // Finally xor secrets with the message
    final_msg.xor_mut(&final_aggregation);

    let mut round_output = RoundOutput {
        round,
        dc_msg: final_msg,
        server_sigs: vec![],
    };

    let (sig, pk) = round_output.sign(&signing_sk.unseal_into()?)?;

    round_output.server_sigs.push(Signature { pk, sig });

    debug!(
        "⏰ round {} concluded with output {:?}",
        round, round_output
    );

    Ok(round_output)
}
