use crate::{
    circuit::tx::{CTransferPub, CTransferSec, c_transfer},
    native::tx::{TransferPub, TransferSec, PoolParams, PoolBN256}
};
use fawkes_crypto::native::bn256::JubJubBN256;
use fawkes_crypto::core::field::Field;
use crate::{IN, OUT, H};
use crate::native::tx::Note;


use typenum::Unsigned;
use fawkes_crypto::native::bn256::{Fr, Fs};
use fawkes_crypto::native::num::Num;
use std::collections::HashMap;


struct ClientState {
    proof_len:usize,
    cell: HashMap<u32, Num<Fr>>,
    nullifier:Vec<Num<Fr>>,
    dk: Num<Fs>
}



pub fn gen_test_data() -> (TransferPub<PoolBN256<IN, OUT, H>>, TransferSec<PoolBN256<IN, OUT, H>>){
    std::unimplemented!()
}