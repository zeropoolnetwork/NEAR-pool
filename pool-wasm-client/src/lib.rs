use fawkes_crypto::core::cs::TestCS;
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::native::bn256::Fr;
use fawkes_crypto::native::ecc::JubJubParams;
use fawkes_crypto::num;
use pool_circuit::circuit::tx::{c_transfer, CTransferPub, CTransferSec};
use pool_circuit::native::data::{rand_biguint, ClientState, NativeWallet};
use pool_circuit::native::tx::{derive_key_pk_d, note_hash, Note, PoolParams, NOTE_CHUNKS};
use pool_circuit::{TPoolParams, POOL_PARAMS};
use rand::Rng;
use wasm_bindgen::prelude::*;

use num::Zero;
use num::{BigInt, BigUint};

mod client;
mod database;
mod random;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const NUM_COLS: u32 = 4;

// For testing purposes
#[wasm_bindgen]
pub async fn create_tx() {
    let db = kvdb_web::Database::open("test".to_owned(), NUM_COLS)
        .await
        .unwrap();

    let mut rng = random::CustomRng::default();

    let wallet = NativeWallet::<TPoolParams> { sk: rng.gen() };

    let state = ClientState::new(&db, &wallet, &*POOL_PARAMS);
    for _ in 0..(1 << 8) {
        let mut note: Note<Fr> = rng.gen();
        note.pk_d = derive_key_pk_d(note.d, state.dk, &*POOL_PARAMS).x;
        let hash = note_hash(note, &*POOL_PARAMS);
        state.add_leaf(hash, Some(note));
    }

    let recv_addr = {
        let d = num!(rand_biguint(&mut rng, NOTE_CHUNKS[0]));
        let pk_d = POOL_PARAMS
            .jubjub()
            .edwards_g()
            .mul(rng.gen(), POOL_PARAMS.jubjub())
            .x;
        (d, pk_d)
    };

    let (p, s, _) = state
        .make_transaction_object(&mut rng, recv_addr, BigUint::from(1u64), BigInt::zero())
        .unwrap();

    let ref mut cs = TestCS::<Fr>::new();

    let mut n_constraints = cs.num_constraints();

    let ref p = CTransferPub::alloc(cs, Some(&p));
    let ref s = CTransferSec::alloc(cs, Some(&s));

    c_transfer(&p, &s, &*POOL_PARAMS);
    n_constraints = cs.num_constraints() - n_constraints;
}
