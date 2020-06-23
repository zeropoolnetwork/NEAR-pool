use fawkes_crypto::native::{
    num::Num, ecc::JubJubParams,
    poseidon::{PoseidonParams, MerkleProof, poseidon_with_salt}
};

use fawkes_crypto::core::{
    sizedvec::SizedVec,
    field::Field
};
use num::bigint::{BigUint};
use num_traits::Num as NumTrait;
use typenum::Unsigned;
use std::fmt::Debug;
use std::marker::PhantomData;
use crate::constants::{SEED_DIVERSIFIER, SEED_DECRYPTION_KEY, SEED_IN_NOTE_HASH, SEED_OUT_NOTE_HASH, SEED_TX_HASH, SEED_NULLIFIER, SEED_NOTE_HASH};

use bellman::pairing::bn256::Fr;

pub trait PoolParams : Clone+Sized {
    type F: Field;
    type J: JubJubParams<Fr=Self::F>;
    type IN:Unsigned;
    type OUT:Unsigned;
    type H:Unsigned;

    fn jubjub(&self) -> &Self::J;
    fn hash(&self) -> &PoseidonParams<Self::F>;
    fn compress(&self) -> &PoseidonParams<Self::F>;
    fn note(&self) -> &PoseidonParams<Self::F>;
    fn tx_in(&self) -> &PoseidonParams<Self::F>;
    fn tx_out(&self) -> &PoseidonParams<Self::F>;
    fn eddsa(&self) -> &PoseidonParams<Self::F>;
}

#[derive(Clone)]
pub struct PoolBN256<J:JubJubParams<Fr=Fr>, IN:Unsigned, OUT:Unsigned, H:Unsigned>{
    pub jubjub:J,
    pub hash: PoseidonParams<Fr>,
    pub compress: PoseidonParams<Fr>,
    pub note: PoseidonParams<Fr>,
    pub tx_in: PoseidonParams<Fr>,
    pub tx_out: PoseidonParams<Fr>,
    pub eddsa: PoseidonParams<Fr>,
    pub phantom: PhantomData<(IN, OUT, H)>
}

impl<J:JubJubParams<Fr=Fr>, IN:Unsigned, OUT:Unsigned, H:Unsigned> PoolParams for PoolBN256<J,IN, OUT, H> {
    type F = Fr;
    type J = J;
    type IN = IN;
    type OUT = OUT;
    type H = H;

    fn jubjub(&self) -> &Self::J {
        &self.jubjub
    }

    fn hash(&self) -> &PoseidonParams<Self::F> {
        &self.hash
    }

    fn compress(&self) -> &PoseidonParams<Self::F> {
        &self.compress
    }

    fn note(&self) -> &PoseidonParams<Self::F> {
        &self.note
    }

    fn tx_in(&self) -> &PoseidonParams<Self::F> {
        &self.tx_in
    }

    fn tx_out(&self) -> &PoseidonParams<Self::F> {
        &self.tx_out
    }

    fn eddsa(&self) -> &PoseidonParams<Self::F> {
        &self.eddsa
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Note<F:Field> {
    pub d: Num<F>,
    pub pk_d: Num<F>,
    pub v: Num<F>,
    pub st: Num<F>
}


#[derive(Debug, Clone)]
pub struct TxPub<P:PoolParams> {
    pub root: Num<P::F>,
    pub nullifier: SizedVec<Num<P::F>, P::IN>,
    pub out_note_hash_root: Num<P::F>,
    pub out_hash: SizedVec<Num<P::F>, P::OUT>,
    pub delta: Num<P::F>,
    pub memo: Num<P::F>
}

#[derive(Debug, Clone)]
pub struct TxSec<P:PoolParams> {
    pub in_note: SizedVec<Note<P::F>, P::IN>,
    pub out_note: SizedVec<Note<P::F>, P::OUT>,
    pub in_proof: SizedVec<MerkleProof<P::F,P::H>, P::IN>,
    pub dk: Num<P::F>,
    pub eddsa_s: Num<P::F>,
    pub eddsa_r: Num<P::F>,
    pub eddsa_a: Num<P::F>
} 



pub fn nullfifier<P:PoolParams>(note_hash:Num<P::F>, dk:Num<P::F>, params:&P) -> Num<P::F>{
    poseidon_with_salt(&[note_hash, dk], SEED_NULLIFIER, params.compress())
}

pub fn note_hash<P:PoolParams>(note: Note<P::F>, params: &P) -> Num<P::F> {
    poseidon_with_salt(&[note.d, note.pk_d, note.v, note.st], SEED_NOTE_HASH, params.note())
}

pub fn tx_hash<P:PoolParams>(in_note_hash: &[Num<P::F>], out_note_hash: &[Num<P::F>], params:&P) -> Num<P::F> {
    let in_h = poseidon_with_salt(&in_note_hash, SEED_IN_NOTE_HASH, params.tx_in());
    let out_h = poseidon_with_salt(&out_note_hash, SEED_OUT_NOTE_HASH, params.tx_out());
    poseidon_with_salt(&[in_h, out_h], SEED_TX_HASH, params.compress())
}

pub fn parse_delta<F:Field>(delta:Num<F>) -> Num<F> {
    let delta_num = Into::<BigUint>::into(delta);
    let min_neg_amount = BigUint::from_str_radix("80000000000000000000000000000000", 16).unwrap();
    let limit_amount = BigUint::from_str_radix("100000000000000000000000000000000", 16).unwrap();
    assert!(delta_num < limit_amount);

    if delta_num < min_neg_amount {
        delta
    } else {
        delta - num!(limit_amount)
    }
}
