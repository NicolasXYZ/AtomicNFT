use crate::interface::*;
use crate::messages_types::AggregatedMessage;
use crate::sgx_tunittest::*;
use crate::std::prelude::v1::*;
use crypto;
use crypto::{SgxSigningKey, SignMutable, Signable};
use hkdf::Hkdf;
use serde_cbor;
use sgx_rand::Rng;
use sgx_types::sgx_status_t;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::iter::FromIterator;
use types::*;

pub fn test_all() -> sgx_status_t {
    // rsgx_unit_tests!(test_agg_msg);
    // rsgx_unit_tests!(scheduler_tests);
    // rsgx_unit_tests!(test_dc_msg);
    rsgx_unit_tests!(sign, hkdf, aggregate, serde_dc_message);
    sgx_status_t::SGX_SUCCESS
}

fn hkdf() {
    // copied from the original test vectors found at
    // https://github.com/bl4ck5un/KDFs/blob/v0.8.0-sgx/hkdf/examples/main.rs
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    let expected =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert_eq!(hex::encode(&okm[..]), expected);
}

fn test_keypair() -> crypto::CryptoResult<(SgxSigningKey, SgxSigningPubKey)> {
    let handle = sgx_tcrypto::SgxEccHandle::new();
    handle.open().unwrap();
    match handle.create_key_pair() {
        Ok(pair) => Ok((crypto::KemPrvKey::from(pair.0), KemPubKey::from(pair.1))),
        Err(e) => Err(CryptoError::SgxCryptoLibError(e)),
    }
}

fn sign() -> () {
    let (sk, pk) = test_keypair().unwrap();

    let mut mutable = AggregatedMessage {
        user_ids: BTreeSet::from_iter(vec![EntityId::default()].into_iter()),
        anytrust_group_id: Default::default(),
        round: 0,
        aggregated_msg: Default::default(),
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    mutable.sign_mut(&sk).expect("sign");

    assert_eq!(mutable.tee_pk, pk);
    assert!(mutable.verify().expect("verify"));
}

fn aggregate() {
    // let (keypair, signed_msg) = sign();
    //
    // let agg = ecall::aggregate_internal(&signed_msg, &AggregatedMessage::zero(), &keypair.prv_key)
    //     .expect("agg");
    //
    // assert!(agg.verify().expect("ver"));
    //
    // // should not change since we agg in a zero message
    // assert_eq!(agg.aggregated_msg, signed_msg.msg);
    //
    // // aggregate again the same message should error
    // assert!(ecall::aggregate_internal(&signed_msg, &agg, &keypair.prv_key).is_err());
    //
    // // let's use a different user id and submit again
    // let mut new_msg = signed_msg;
    // new_msg.user_id = EntityId::from([1 as u8; 32]);
    // new_msg.sign_mut(&keypair.prv_key).expect("sig");
    // // aggregate same message twice so we should get zero.
    // let agg = ecall::aggregate_internal(&new_msg, &agg, &keypair.prv_key).expect("agg");
    // assert!(agg.verify().expect("ver"));
    // assert_eq!(agg.aggregated_msg, DcMessage::zero());
}

fn serde_dc_message() {
    let mut rand = sgx_rand::SgxRng::new().unwrap();

    for _i in 0..1000 {
        let sample = rand.gen::<DcMessage>();

        let data = serde_cbor::to_vec(&sample).expect("ser");
        let c: DcMessage = serde_cbor::from_slice(&data).expect("de");

        assert_eq!(c, sample);
    }
}
