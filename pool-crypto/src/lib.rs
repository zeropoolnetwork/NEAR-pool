#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

pub mod circuit;
pub mod constants;
pub mod native;

use crate::native::tx::PoolBN256;

use pairing::bn256::Fr;
use typenum::{Unsigned, U2, U32, U6};

use fawkes_crypto::native::bn256::JubJubBN256;
use fawkes_crypto::native::poseidon::PoseidonParams;

use lazy_static::lazy_static;
use std::marker::PhantomData;

pub type IN = U6;
pub type OUT = U2;
pub type H = U32;

lazy_static! {
    pub static ref POOL_PARAMS: PoolBN256<IN, OUT, H> = PoolBN256::<IN, OUT, H> {
        jubjub: JubJubBN256::new(),
        hash: PoseidonParams::<Fr>::new(2, 8, 53),
        compress: PoseidonParams::<Fr>::new(3, 8, 53),
        note: PoseidonParams::<Fr>::new(5, 8, 54),
        tx: PoseidonParams::<Fr>::new(IN::USIZE + OUT::USIZE + 1, 8, 54),
        eddsa: PoseidonParams::<Fr>::new(4, 8, 53),
        phantom: PhantomData
    };
}
