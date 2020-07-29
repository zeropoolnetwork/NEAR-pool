use crate::{
    native::tx::{
        note_encrypt, note_hash, nullfifier, tx_hash, Note, PoolBN256, PoolParams, TransferPub,
        TransferSec, Tx,
    },
};

use fawkes_crypto::core::field::Field;

use crate::{H, IN, OUT};
use num::bigint::{Sign, ToBigInt};
use num::{BigInt, BigUint};
use num::{One, Zero};

use fawkes_crypto::core::sizedvec::SizedVec;
use fawkes_crypto::native::num::Num;
use std::marker::PhantomData;
use typenum::Unsigned;


use fawkes_crypto::borsh::{BorshDeserialize, BorshSerialize};
use fawkes_crypto::native::eddsaposeidon::eddsaposeidon_sign;
use fawkes_crypto::native::poseidon::{poseidon, MerkleProof};
use sha3::{Digest, Keccak256};

use kvdb::{KeyValueDB, DBTransaction};


use crate::native::tx::{derive_key_dk, derive_key_xsk, derive_key_pk_d, NOTE_CHUNKS};


use kvdb_memorydb::{self, InMemory};
use crate::{POOL_PARAMS, TPoolParams};
use fawkes_crypto::native::bn256::{Fr, Fs};
use fawkes_crypto::native::ecc::JubJubParams;
use fawkes_crypto::core::cs::TestCS;
use rand::{thread_rng, Rand, Rng};
use std::time::{Instant};
use crate::circuit::tx::{c_transfer, CTransferPub, CTransferSec};
use fawkes_crypto::core::signal::Signal;

pub fn rand_biguint<R: Rng>(rng: &mut R, bits: usize) -> BigUint {
    let bytes = (bits - 1) / 8 + 1;
    let mut v: Vec<u8> = (0..bytes).map(|_| rng.gen()).collect();
    v[0] >>= bytes * 8 - bits;
    BigUint::from_bytes_be(&v)
}

pub fn prepare_delta<F: Field>(mut delta: BigInt) -> Num<F> {
    let limit_amount = BigInt::one() << (NOTE_CHUNKS[2] * 8);

    if delta.sign() == Sign::Minus {
        delta += &limit_amount;
    }
    assert!(delta >= BigInt::zero() && delta < limit_amount);

    num!(delta.to_biguint().unwrap())
}

pub trait Wallet<P:PoolParams> {
    fn xsk(&self, params:&P) -> Num<P::Fr>;
    fn sign(&self, msg:Num<P::Fr>, params:&P) -> (Num<P::Fs>, Num<P::Fr>);
}

pub struct NativeWallet<P:PoolParams> {
    pub sk: Num<P::Fs>
}

impl<P:PoolParams> Wallet<P> for NativeWallet<P> {
    fn xsk(&self, params: &P) -> Num<P::Fr> {
        derive_key_xsk(self.sk, params).x
    }

    fn sign(&self, msg:Num<P::Fr>, params:&P) -> (Num<P::Fs>, Num<P::Fr>) {
        eddsaposeidon_sign(self.sk, msg, params.eddsa(), params.jubjub())
    }
}

pub struct ClientState<'p, 'db, 'w, P: PoolParams, DB:KeyValueDB, W:Wallet<P>> {
    pub db: &'db DB,
    pub wallet: &'w W,
    pub dk: Num<P::Fs>,
    pub xsk: Num<P::Fr>,
    pub default_cell_value: Vec<Num<P::Fr>>,
    pub params: &'p P,
}

const KEY_INITIALIZED: &[u8] = b"initialized";
const KEY_NUM_LEAVES: &[u8] = b"num_leaves";

const COL_DEFAULT: u32 = 0;
const COL_CELL: u32 = 1;
const COL_NULLIFIER: u32 = 2;
const COL_NOTE: u32 = 2;

const NUM_COLS: usize = 4;


impl<'p, 'db, 'w, P: PoolParams, DB:KeyValueDB, W:Wallet<P>> ClientState<'p, 'db, 'w, P, DB, W> {
    pub fn new(db: &'db DB, wallet: &'w W, params: &'p P) -> Self {
        if db.get(COL_DEFAULT, KEY_INITIALIZED).unwrap().is_none() {
            let mut tx = DBTransaction::new();
            tx.put(COL_DEFAULT, KEY_INITIALIZED, &[1u8]);
            tx.put(COL_DEFAULT, KEY_NUM_LEAVES, &0u64.try_to_vec().unwrap());
            db.write(tx).unwrap();
        }

        let xsk = wallet.xsk(params);
        let dk = derive_key_dk(xsk, params);

        let mut default_cell_value: Vec<Num<P::Fr>> = vec![num!(0); H::USIZE + 1];
        for i in 0..H::USIZE {
            let c = default_cell_value[i];
            default_cell_value[i + 1] = poseidon(&[c, c], params.compress());
        }

        Self {
            db,
            wallet,
            dk,
            xsk,
            default_cell_value,
            params,
        }
    }


    fn get_cell(&self, pos: (usize, usize)) -> Num<P::Fr> {
        let key = (pos.0 as u64, pos.1 as u64).try_to_vec().unwrap();
        self.db.get(COL_CELL, &key).unwrap()
            .map(|v| <Num<P::Fr>>::try_from_slice(&v).unwrap())
            .unwrap_or(self.default_cell_value[pos.0])
    }

    fn set_cell(&self, tx: &mut DBTransaction, pos: (usize, usize), v: Num<P::Fr>) {
        let key = (pos.0 as u64, pos.1 as u64).try_to_vec().unwrap();
        tx.put(COL_CELL, &key, &v.try_to_vec().unwrap());
    }


    fn get_note(&self, pos: usize) -> Option<Note<P::Fr>> {
        let key = (pos as u64).try_to_vec().unwrap();
        self.db.get(COL_NOTE, &key).unwrap()
            .map(|v| <Note<P::Fr>>::try_from_slice(&v).unwrap())
    }

    fn set_note(&self, tx: &mut DBTransaction, pos: usize, v: Note<P::Fr>) {
        let key = (pos as u64).try_to_vec().unwrap();
        tx.put(COL_NOTE, &key, &v.try_to_vec().unwrap());
    }

    fn gen_num_leaves(&self) -> usize {
        self.db.get(COL_DEFAULT, KEY_NUM_LEAVES).unwrap()
            .map(|v| u64::try_from_slice(&v).unwrap() as usize).unwrap()
    }

    fn set_num_leaves(&self, tx: &mut DBTransaction, v: usize) {
        tx.put(COL_DEFAULT, KEY_NUM_LEAVES, &(v as u64).try_to_vec().unwrap());
    }

    fn update_merkle_path(&self, tx: &mut DBTransaction, mut pos: usize, value: Num<P::Fr>) {
        let mut root = value;
        self.set_cell(tx, (0, pos), value);

        for i in 0..H::USIZE {
            root = if pos & 1 == 1 {
                poseidon(&[self.get_cell((i, pos-1)), root], self.params.compress())
            } else {
                poseidon(&[root, self.get_cell((i, pos+1))], self.params.compress())
            };
            pos >>= 1;
            self.set_cell(tx, (i + 1, pos), root);
        }
    }

    fn get_merkle_proof(&self, pos: usize) -> MerkleProof<P::Fr, P::H> {
        let sibling = (0..P::H::USIZE)
            .map(|i| self.get_cell((i, (pos >> i) ^ 1)))
            .collect();
        let path = (0..P::H::USIZE).map(|i| (pos >> i) & 1 == 1).collect();
        MerkleProof { sibling, path }
    }

    pub fn add_leaf(&self, note_hash: Num<P::Fr>, note: Option<Note<P::Fr>>) {
        let num_leaves = self.gen_num_leaves();
        let mut tx = DBTransaction::new();
        self.update_merkle_path(&mut tx, num_leaves, note_hash);
        if let Some(note) = note {
            self.set_note(&mut tx, num_leaves, note);
        }
        self.set_num_leaves(&mut tx,num_leaves + 1);
        self.db.write(tx).unwrap()
    }

    pub fn get_note_list(&self) -> Vec<(usize,Note<P::Fr>)> {
        self.db.iter(COL_NOTE)
            .map(|(k, v)| 
                (u64::try_from_slice(&k).unwrap() as usize, <Note<P::Fr>>::try_from_slice(&v).unwrap())
            ).collect()
    }

    pub fn total_balance(&self) -> Num<P::Fr> {
        self.get_note_list().into_iter()
            .fold(num!(0), |acc, item| acc + item.1.v)
    }

    pub fn make_transaction_object<R: Rng>(
        &self,
        rng: &mut R,
        recv_addr: (Num<P::Fr>, Num<P::Fr>),
        amount: BigUint,
        delta: BigInt,
    ) -> Option<(TransferPub<P>, TransferSec<P>, Vec<u8>)> {
        assert!(P::OUT::USIZE >= 2);

        let mut note = self.get_note_list().into_iter()
            .map(|e| (e.0, e.1, Into::<BigUint>::into(e.1.v)))
            .collect::<Vec<_>>();
        note.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    
        let mut spending_amount: BigUint =
            note.iter().take(P::IN::USIZE).map(|e| e.2.clone()).sum();

        spending_amount = (spending_amount.to_bigint().unwrap() + &delta).to_biguint()?;

        if spending_amount < amount {
            None
        } else {
            let mut indexes: Vec<usize> = (0..std::cmp::min(P::IN::USIZE, note.len())).collect();
            let note_len = note.len();
            if note.len() > P::IN::USIZE {
                for i in 0..P::IN::USIZE {
                    let i1 = P::IN::USIZE - i - 1;
                    let i2 = note_len - i - 1;

                    let delta = &note[i1].2 - &note[i2].2;
                    if &spending_amount - &delta < amount {
                        break;
                    }
                    spending_amount -= delta;
                    indexes[i1] = i2;
                }
            }

            let sender_note = {
                let d = num!(rand_biguint(rng, NOTE_CHUNKS[0]));
                let pk_d = derive_key_pk_d(d, self.dk, self.params).x;
                let v = num!(&spending_amount - &amount);
                let st = num!(rand_biguint(rng, NOTE_CHUNKS[3]));

                Note { d, pk_d, v, st }
            };


            let receiver_note = {
                let (d, pk_d) = recv_addr;
                let v = num!(amount);
                let st = num!(rand_biguint(rng, NOTE_CHUNKS[3]));

                Note { d, pk_d, v, st }
            };

            let tx = {
                let input = indexes
                    .iter()
                    .map(|&i| note[i].1.clone())
                    .chain((indexes.len()..P::IN::USIZE).map(|_| Note {
                        d: num!(rand_biguint(rng, NOTE_CHUNKS[0])),
                        pk_d: rng.gen(),
                        v: num!(0),
                        st: num!(rand_biguint(rng, NOTE_CHUNKS[3])),
                    }))
                    .collect();

                let output = [sender_note, receiver_note]
                    .iter()
                    .cloned()
                    .chain((2..P::OUT::USIZE).map(|_| Note {
                        d: num!(rand_biguint(rng, NOTE_CHUNKS[0])),
                        pk_d: rng.gen(),
                        v: num!(0),
                        st: num!(rand_biguint(rng, NOTE_CHUNKS[3])),
                    }))
                    .collect();

                Tx { input, output }
            };

            let assets = {
                let mut res = vec![];
                for n in tx.output.iter() {
                    let esk = rng.gen();
                    res.extend(note_encrypt(esk, self.dk, *n, self.params));
                }
                res
            };

            let memo = {
                let mut h = Keccak256::new();
                h.update(&assets);
                let hash = h.finalize();
                Num::from_binary_be(&hash)
            };

            let in_proof = indexes
                .iter()
                .map(|&i| self.get_merkle_proof(note[i].0))
                .chain((indexes.len()..P::IN::USIZE).map(|_| MerkleProof {
                    sibling: SizedVec(vec![num!(0); P::H::USIZE], PhantomData),
                    path: SizedVec(vec![false; P::H::USIZE], PhantomData),
                }))
                .collect();
            let in_note_hash = tx
                .input
                .iter()
                .map(|&e| note_hash(e, self.params))
                .collect::<Vec<_>>();
            let out_note_hash = tx
                .output
                .iter()
                .map(|&e| note_hash(e, self.params))
                .collect::<SizedVec<_, P::OUT>>();

            let (eddsa_s, eddsa_r, eddsa_a) = {
                let m = tx_hash(&in_note_hash, &out_note_hash.0, self.params);
                let (s, r) = self.wallet.sign(m, &self.params);
                (s.into_other(), r, self.xsk)
            };

            let transfer_sec = TransferSec {
                tx,
                in_proof,
                eddsa_s,
                eddsa_r,
                eddsa_a,
            };

            let transfer_pub = {
                let root = self.get_cell((P::H::USIZE, 0));
                let nullifier = in_note_hash
                    .iter()
                    .map(|&e| nullfifier(e, self.xsk, self.params))
                    .collect();
                let out_hash = out_note_hash;
                let delta = prepare_delta(delta);

                TransferPub {
                    root,
                    nullifier,
                    out_hash,
                    delta,
                    memo,
                }
            };

            Some((transfer_pub, transfer_sec, assets))
        }
    }
}

pub fn gen_test_data() -> (
    TransferPub<PoolBN256<IN, OUT, H>>,
    TransferSec<PoolBN256<IN, OUT, H>>,
) {
    let db = kvdb_memorydb::create(NUM_COLS as u32);
    let mut rng = thread_rng();
    let wallet = NativeWallet::<TPoolParams> {sk: rng.gen()};

    let state = ClientState::new(&db, &wallet, &*POOL_PARAMS);
    for i in 0..(1<<8) {
        let mut note: Note<Fr> = rng.gen();
        note.pk_d = derive_key_pk_d(note.d, state.dk, &*POOL_PARAMS).x;
        let hash = note_hash(note, &*POOL_PARAMS);
        state.add_leaf(hash, Some(note));
    }

    let recv_addr = {
        let d = num!(rand_biguint(&mut rng, NOTE_CHUNKS[0]));
        let pk_d = POOL_PARAMS.jubjub().edwards_g().mul(rng.gen(), POOL_PARAMS.jubjub()).x;
        (d, pk_d)
    };

    let (p,s, _) = state.make_transaction_object(&mut rng, recv_addr, BigUint::from(1u64), BigInt::zero()).unwrap();
    (p, s)

}

#[cfg(test)]
mod data_test {
    use super::*;



    #[test]
    fn test_transfer() {
        let db = kvdb_memorydb::create(NUM_COLS as u32);
        let mut rng = thread_rng();
        let wallet = NativeWallet::<TPoolParams> {sk: rng.gen()};

        let state = ClientState::new(&db, &wallet, &*POOL_PARAMS);
        for i in 0..(1<<8) {
            let mut note: Note<Fr> = rng.gen();
            note.pk_d = derive_key_pk_d(note.d, state.dk, &*POOL_PARAMS).x;
            let hash = note_hash(note, &*POOL_PARAMS);
            state.add_leaf(hash, Some(note));
        }

        let recv_addr = {
            let d = num!(rand_biguint(&mut rng, NOTE_CHUNKS[0]));
            let pk_d = POOL_PARAMS.jubjub().edwards_g().mul(rng.gen(), POOL_PARAMS.jubjub()).x;
            (d, pk_d)
        };

        let (p, s, _) = state.make_transaction_object(&mut rng, recv_addr, BigUint::from(1u64), BigInt::zero()).unwrap();

        let ref mut cs = TestCS::<Fr>::new();

        let mut n_constraints = cs.num_constraints();
        let start = Instant::now();

        let ref p = CTransferPub::alloc(cs, Some(&p));
        let ref s = CTransferSec::alloc(cs, Some(&s));

        c_transfer(&p, &s, &*POOL_PARAMS);
        let duration = start.elapsed();
        n_constraints=cs.num_constraints()-n_constraints;

        println!("tx constraints = {}", n_constraints);
        println!("Time elapsed in c_transfer() is: {:?}", duration);


    }
}