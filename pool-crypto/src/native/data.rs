use crate::{
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    native::tx::{
        note_encrypt, note_hash, nullfifier, tx_hash, Note, PoolBN256, PoolParams, TransferPub,
        TransferSec, Tx,
    },
};

use fawkes_crypto::core::field::Field;
use fawkes_crypto::native::bn256::JubJubBN256;
use rocksbin::{Prefix, DB};

use crate::{H, IN, OUT};
use num::bigint::{Sign, ToBigInt, ToBigUint};
use num::{BigInt, BigUint};
use num::{One, Zero};

use fawkes_crypto::core::sizedvec::SizedVec;
use fawkes_crypto::native::bn256::{Fr, Fs};
use fawkes_crypto::native::num::Num;
use std::collections::HashMap;
use std::marker::PhantomData;
use typenum::Unsigned;

use base64::decode;
use dotenv::dotenv;
use fawkes_crypto::borsh::{BorshDeserialize, BorshSerialize};
use fawkes_crypto::native::ecc::JubJubParams;
use fawkes_crypto::native::eddsaposeidon::eddsaposeidon_sign;
use fawkes_crypto::native::poseidon::{poseidon, poseidon_with_salt, MerkleProof};
use sha3::{Digest, Keccak256};
use std::env;

use crate::native::tx::{derive_key_dk, derive_key_pk, derive_key_pk_d, NOTE_CHUNKS};
use crate::POOL_PARAMS;

use rand::{Rand, Rng};

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

pub struct ClientState<'p, P: PoolParams> {
    pub db: DB,
    pub cell: Prefix<(usize, usize), Num<P::F>>,
    pub nullifier: Prefix<Num<P::F>, bool>,
    pub note: Prefix<usize, Note<P::F>>,
    pub num_leaves: Prefix<(), usize>,
    pub dk: Num<<P::J as JubJubParams>::Fs>,
    pub sk: Num<<P::J as JubJubParams>::Fs>,
    pub pk: Num<P::F>,
    pub default_cell_value: Vec<Num<P::F>>,
    pub params: &'p P,
}

impl<'p, P: PoolParams> ClientState<'p, P> {
    pub fn new(params: &'p P) -> Self {
        let db = DB::open("db").unwrap();
        let cell = db.prefix::<(usize, usize), Num<P::F>>(b"cell").unwrap();
        let nullifier = db.prefix::<Num<P::F>, bool>(b"nullifier").unwrap();
        let note = db.prefix::<usize, Note<P::F>>(b"note").unwrap();
        let num_leaves = db.prefix::<(), usize>(b"num_leaves").unwrap();

        dotenv().ok();

        let sk_base64 = env::vars()
            .find_map(|e| {
                if e.0 == "PRIVATE_KEY" {
                    Some(e.1)
                } else {
                    None
                }
            })
            .unwrap();
        let sk =
            Num::<<P::J as JubJubParams>::Fs>::try_from_slice(&decode(sk_base64).unwrap()).unwrap();

        let pk = derive_key_pk(sk, params).x;
        let dk = derive_key_dk(pk, params);

        let mut default_cell_value: Vec<Num<P::F>> = vec![num!(0); H::USIZE + 1];
        for i in 0..H::USIZE {
            let c = default_cell_value[i];
            default_cell_value[i + 1] = poseidon(&[c, c], params.compress());
        }

        Self {
            db,
            cell,
            nullifier,
            note,
            dk,
            sk,
            pk,
            num_leaves,
            default_cell_value,
            params,
        }
    }

    fn get_cell(&self, pos: (usize, usize)) -> Num<P::F> {
        self.cell
            .get(&pos)
            .unwrap()
            .unwrap_or(self.default_cell_value[pos.0])
    }

    fn set_cell(&self, pos: (usize, usize), v: Num<P::F>) {
        self.cell.insert(&pos, &v).unwrap();
    }

    fn gen_num_leaves(&self) -> usize {
        self.num_leaves.get(&()).unwrap().unwrap_or(0)
    }

    fn set_num_leaves(&self, v: usize) {
        self.num_leaves.insert(&(), &v).unwrap();
    }

    fn update_merkle_path(&self, mut pos: usize) {
        for i in 0..H::USIZE {
            pos >>= 1;
            let h = poseidon(
                &[self.get_cell((i, pos * 2)), self.get_cell((i, pos * 2 + 1))],
                self.params.compress(),
            );
            self.set_cell((i + 1, pos), h);
        }
    }

    fn get_merkle_proof(&self, pos: usize) -> MerkleProof<P::F, P::H> {
        let sibling = (0..P::H::USIZE)
            .map(|i| self.get_cell((i, (pos >> i) ^ 1)))
            .collect();
        let path = (0..P::H::USIZE).map(|i| (pos >> i) & 1 == 1).collect();
        MerkleProof { sibling, path }
    }

    pub fn add_leaf(&self, note_hash: Num<P::F>, note: Option<Note<P::F>>) {
        let num_leaves = self.gen_num_leaves();
        self.set_cell((0, num_leaves), note_hash);
        self.update_merkle_path(num_leaves);
        self.set_num_leaves(num_leaves + 1);

        if let Some(note) = note {
            self.note.insert(&num_leaves, &note).unwrap();
        }
    }

    pub fn total_balance(&self) -> Num<P::F> {
        let mut r = num!(0);
        for v in self.note.values() {
            r += v.unwrap().v;
        }
        r
    }

    pub fn make_transaction_object<R: Rng>(
        &self,
        rng: &mut R,
        recv_addr: (Num<P::F>, Num<P::F>),
        amount: BigUint,
        delta: BigInt,
    ) -> Option<(TransferPub<P>, TransferSec<P>, Vec<u8>)> {
        assert!(P::OUT::USIZE >= 2);

        let mut note = self
            .note
            .iter()
            .map(|e| {
                let e = e.unwrap();
                (e.0, e.1, Into::<BigUint>::into(e.1.v))
            })
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
                let (s, r) =
                    eddsaposeidon_sign(self.sk, m, self.params.eddsa(), self.params.jubjub());
                (s.into_other(), r, self.pk)
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
                    .map(|&e| nullfifier(e, self.pk, self.params))
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
    std::unimplemented!()
}
