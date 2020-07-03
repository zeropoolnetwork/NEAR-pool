#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

pub mod circuit;
pub mod native;
pub mod constants;

use crate::native::gen_test_data::gen_test_data;

use crate::{
    circuit::tx::{CTransferPub, CTransferSec, c_transfer},
    native::tx::{TransferPub, TransferSec, PoolBN256}
};

use typenum::{U6, U2, U32, Unsigned};
use pairing::bn256::{Fr};

use fawkes_crypto::native::poseidon::PoseidonParams;
use fawkes_crypto::native::bn256::JubJubBN256;

use lazy_static::lazy_static;
use std::marker::PhantomData;

pub type IN = U6;
pub type OUT = U2;
pub type H = U32;

lazy_static! {
    pub static ref POOL_PARAMS: PoolBN256<JubJubBN256, IN, OUT, H> = PoolBN256::<JubJubBN256, IN, OUT, H> {
        jubjub:JubJubBN256::new(),
        hash: PoseidonParams::<Fr>::new(2, 8, 53),
        compress: PoseidonParams::<Fr>::new(3, 8, 53),
        note: PoseidonParams::<Fr>::new(5, 8, 54),
        tx: PoseidonParams::<Fr>::new(IN::USIZE+OUT::USIZE+1, 8, 54),
        eddsa: PoseidonParams::<Fr>::new(4, 8, 53),
        phantom: PhantomData
    };

}


groth16_near_bindings!(cli, TransferPub<PoolBN256<JubJubBN256, IN, OUT, H>>, CTransferPub, TransferSec<PoolBN256<JubJubBN256, IN, OUT, H>>, CTransferSec, POOL_PARAMS, c_transfer, gen_test_data);

fn main() {
    cli::cli_main()
}