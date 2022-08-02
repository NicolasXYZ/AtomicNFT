#![no_std]

extern crate sgx_types;
#[macro_use]
extern crate sgx_tstd as std;
extern crate interface;
extern crate sgx_tcrypto;
extern crate sgx_tse;
extern crate sgx_tunittest;

#[macro_use]
extern crate quick_error;

extern crate byteorder;
extern crate hex;
extern crate hkdf;
extern crate sha2;

#[macro_use]
extern crate serde;
extern crate serde_cbor;

#[macro_use]
extern crate log;
extern crate bitvec;
extern crate env_logger;

use sgx_types::*;

extern crate sgx_rand;
extern crate sgx_trts;
extern crate sgx_tseal;

mod attestation;
mod crypto;
mod ecall;
mod messages_types;
mod tests;
mod types;
mod unseal;

#[no_mangle]
pub extern "C" fn test_main_entrance() -> sgx_status_t {
    tests::test_all()
}
