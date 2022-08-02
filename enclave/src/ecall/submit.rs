extern crate interface;
extern crate sgx_types;

use self::interface::*;
use crate::crypto::Xor;
use crate::messages_types::AggregatedMessage;
use crate::unseal::{MarshallAs, UnsealableInto};
use attestation::Attested;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use core::convert::TryInto;
use crypto;
use crypto::{MultiSignable, SgxPrivateKey, SharedSecretsDb, SignMutable};
use interface::UserSubmissionReq;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_tcrypto::SgxEccHandle;
use sgx_types::sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE;
use sgx_types::{SgxError, SgxResult};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::debug;
use std::iter::FromIterator;
use std::prelude::v1::*;
use unseal::SealInto;

/// process user submission request
/// returns a submission and the ratcheted shared secrets
pub fn user_submit_internal(
    (send_request, signing_sk): &(UserSubmissionReq, SealedSigPrivKey),
) -> SgxResult<(RoundSubmissionBlob, SealedSharedSecretDb)> {
    // unseal user's sk
    let signing_sk = signing_sk.unseal_into()?;
    // Determine whether the message is just cover traffic (all zeroes)
    let msg_is_empty = send_request.msg.0.iter().all(|b| *b == 0);

    // check user signing key matches user_id
    if EntityId::from(&SgxSigningPubKey::try_from(&signing_sk)?) != send_request.user_id {
        error!("user id mismatch");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let uid = &send_request.user_id;

    debug!("✅ user id {} matches user signing key", uid);

    // check server pks against TEE attestation
    if !send_request
        .server_pks
        .iter()
        .all(|pk| pk.verify_attestation())
    {
        error!("some PKs not verified");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let mut server_sig_pks = Vec::new();
    let mut server_kem_pks = Vec::new();
    // check anytrust group id matches server pubkeys
    for pk_pkg in send_request.server_pks.iter() {
        server_sig_pks.push(pk_pkg.sig);
        server_kem_pks.push(pk_pkg.kem);
    }

    // check anytrust_group_id against the (now verified) kem keys
    if send_request.anytrust_group_id != compute_anytrust_group_id(&server_kem_pks) {
        error!("reserve_req.anytrust_group_id != EntityId::from(server_sig_pks)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    debug!("✅ shared secrets matches anytrust groupid");

    // make a new footprint
    let (cur_slot, cur_fp, next_slot, next_fp) = derive_reservation(
        &signing_sk,
        &send_request.anytrust_group_id,
        send_request.round,
    );

    // since the scheduling vector is potentially a lot larger than the dc net message vector (to
    // avoid collision), we expect many slots in the scheduling vector to be empty. To save
    // bandwidth we compact the dc net message by skipping slots that are not scheduled
    //
    // e.g., if scheduling msg is [100, 0, 0, 676] and the sender is scheduled at the 4th slot
    // (fp=676), then she should send in the 2nd slot in the dc net vector because two slots are
    // empty.
    // cur_slot is the reserved slot # in the scheduling vector (3 in the above example)
    // msg_slot = the number of non-empty footprints in slot [0...cur_slot)
    // msg_slot = 1 in the above example
    let mut msg_slot = cur_slot;
    for s in 0..cur_slot {
        // skip empty slots
        if send_request.prev_round_output.dc_msg.scheduling_msg[s] == 0 {
            msg_slot -= 1;
        }
    }

    if msg_slot > DC_NET_N_SLOTS {
        error!("❌ can't send. scheduling failure. you need to wait for the next round.");
        return Err(SGX_ERROR_SERVICE_UNAVAILABLE);
    }

    // drop mut
    let msg_slot: usize = msg_slot;

    debug!("✅ user {} will try to send in slot {}", uid, msg_slot);

    // Check the scheduling result from the previous round (the ticket) unless
    // a) this is the first round (round = 0) or
    // b) req.msg is all zeroes (i.e., the user is not sending anything but just scheduling).
    if send_request.round == 0 {
        debug!(
            "✅ user {} is permitted to send at slot {} because it's round 0",
            uid, msg_slot
        );
    } else if msg_is_empty {
        debug!(
            "✅ user {} is permitted to send at slot {} because msg is all-zero",
            uid, msg_slot
        );
    } else {
        // validate the request
        if send_request.round != send_request.prev_round_output.round + 1 {
            error!("wrong round #");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        // verify server's signatures on previous output
        let verified_index = send_request
            .prev_round_output
            .verify_multisig(&server_sig_pks)?;

        if verified_index.is_empty() {
            error!("❌ sigs in prev_round_output can't be verified");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        info!("✅ prev_round_output verified against {:?}", verified_index);

        // now that sigs on prev_round_output are checked we check the footprints therein
        if send_request.prev_round_output.dc_msg.scheduling_msg[cur_slot] != cur_fp {
            error!(
                "❌ Collision in slot {} for round {}. sent fp {} != received fp {}. ",
                msg_slot,
                send_request.round,
                send_request.prev_round_output.dc_msg.scheduling_msg[cur_slot],
                cur_fp,
            );
            return Err(SGX_ERROR_SERVICE_UNAVAILABLE);
        }
        debug!(
            "✅ user {} is permitted to send msg at slot {} for round {}",
            uid, msg_slot, send_request.round
        );
    }

    debug!(
        "✅ user is scheduled for slot {} for next round with fp {}",
        next_slot, next_fp,
    );

    // Put user message in the designated slot of the round message
    let mut round_msg = DcRoundMessage::default();
    round_msg.scheduling_msg[next_slot] = next_fp;
    round_msg.aggregated_msg[msg_slot] = send_request.msg.clone();

    debug!(
        "✅ slot {} will include msg {:?}",
        msg_slot, send_request.msg,
    );

    // Derive the round key from shared secrets
    let shared_secrets = send_request.shared_secrets.unseal_into()?;
    if shared_secrets.round != send_request.round {
        error!(
            "shared_secrets.round {} != send_request.round {}",
            shared_secrets.round, send_request.round,
        );
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }
    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // debug!("round msg: {:?}", round_msg);

    let round_key = match crypto::derive_round_secret(send_request.round, &shared_secrets) {
        Ok(k) => k,
        Err(e) => {
            error!("can't derive round secret {}", e);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    // encrypt the message with round_key
    let encrypted_msg = round_key.xor(&round_msg);

    let mut mutable = AggregatedMessage {
        user_ids: BTreeSet::from_iter(vec![send_request.user_id].into_iter()),
        anytrust_group_id: send_request.anytrust_group_id,
        round: send_request.round,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
        aggregated_msg: encrypted_msg,
    };

    // sign
    if mutable.sign_mut(&signing_sk).is_err() {
        error!("can't sign");
        return Err(SGX_ERROR_UNEXPECTED);
    }

    // if everything is fine, we are ready to ratchet
    Ok((mutable.marshal()?, shared_secrets.ratchet().seal_into()?))
}

/// Return deterministically derived footprint reservation for the given parameter
///
/// ```
/// if epoch == 0:
///         Let prev_slot_idx = H("first-slot-idx", usk, anytrust_group_id)
///         Let prev_slot_val = H("first-slot-val", usk, anytrust_group_id)
/// else:
/// 		Let prev_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, round-1)
/// 		Let prev_slot_val = H("sched-slot-val", usk, anytrust_group_id, round-1)
/// Let next_slot_idx = H("sched-slot-idx", usk, anytrust_group_id, round)
/// Let next_slot_val = H("sched-slot-val", usk, anytrust_group_id, round)
///
/// return (prev_slot_idx, prev_slot_val, next_slot_idx, next_slot_val)
/// ```
fn derive_reservation(
    usk: &SgxPrivateKey,
    anytrust_group_id: &EntityId,
    round: u32,
) -> (usize, interface::Footprint, usize, interface::Footprint) {
    const FIRST_SLOT_IDX: &[u8; 14] = b"first-slot-idx";
    const FIRST_SLOT_VAL: &[u8; 14] = b"first-slot-val";
    const SCHED_SLOT_IDX: &[u8; 14] = b"sched-slot-idx";
    const SCHED_SLOT_VAL: &[u8; 14] = b"sched-slot-val";

    // hash three things to u32
    let h3_to_u32 = |label: &[u8; 14], usk: &SgxPrivateKey, anytrust_group_id: &EntityId| {
        let mut h = Sha256::new();
        h.input(label);
        h.input(usk);
        h.input(anytrust_group_id);

        let hash = h.result().to_vec();

        (LittleEndian::read_u32(&hash))
    };

    // hash three things to u32
    let h4_to_u32 =
        |label: &[u8; 14], usk: &SgxPrivateKey, anytrust_group_id: &EntityId, round: u32| {
            let mut h = Sha256::new();
            h.input(label);
            h.input(usk);
            h.input(anytrust_group_id);
            h.input(round.to_le_bytes());

            let hash = h.result().to_vec();

            LittleEndian::read_u32(&hash)
        };

    let (prev_slot_idx, prev_slot_val) = {
        if round == 0 {
            (
                h3_to_u32(FIRST_SLOT_IDX, usk, anytrust_group_id) as usize,
                h3_to_u32(FIRST_SLOT_VAL, usk, anytrust_group_id),
            )
        } else {
            (
                h4_to_u32(SCHED_SLOT_IDX, usk, anytrust_group_id, round - 1) as usize,
                h4_to_u32(SCHED_SLOT_VAL, usk, anytrust_group_id, round - 1),
            )
        }
    };

    let next_slot_idx = h4_to_u32(SCHED_SLOT_IDX, usk, anytrust_group_id, round) as usize;
    let next_slot_val = h4_to_u32(SCHED_SLOT_VAL, usk, anytrust_group_id, round);

    (
        prev_slot_idx % FOOTPRINT_N_SLOTS,
        prev_slot_val,
        next_slot_idx % FOOTPRINT_N_SLOTS,
        next_slot_val,
    )
}

/// 1. Check the signature on the preivous round output against a signing key (might have to change API a bit for that)
/// 2. Check that the current round is prev_round+1
/// 3. Make a new footprint reservation for this round
pub fn user_reserve_slot(
    (req, signing_sk): &(UserReservationReq, SealedSigPrivKey),
) -> SgxResult<(RoundSubmissionBlob, SealedSharedSecretDb)> {
    user_submit_internal(&(
        UserSubmissionReq {
            user_id: req.user_id,
            anytrust_group_id: req.anytrust_group_id,
            round: req.round,
            msg: Default::default(),
            prev_round_output: Default::default(),
            shared_secrets: req.shared_secrets.clone(),
            server_pks: req.server_pks.clone(),
        },
        signing_sk.clone(),
    ))
}
