use crate::{
    circuit::tx::{CTransferPub, CTransferSec, c_transfer},
    native::tx::{TransferPub, TransferSec, PoolParams, PoolBN256}
};
use fawkes_crypto::native::bn256::JubJubBN256;
use crate::{IN, OUT, H};



pub fn gen_test_data() -> (TransferPub<PoolBN256<JubJubBN256, IN, OUT, H>>, TransferSec<PoolBN256<JubJubBN256, IN, OUT, H>>){
    std::unimplemented!()
}