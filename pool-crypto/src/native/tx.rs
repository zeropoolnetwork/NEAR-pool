use fawkes_crypto::native::{
    num::Num, ecc::{JubJubParams, EdwardsPoint},
    poseidon::{PoseidonParams, MerkleProof, poseidon_with_salt},
    eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify}
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
use crate::constants::{SEED_DIVERSIFIER, SEED_DECRYPTION_KEY, SEED_TX_HASH, SEED_NULLIFIER, SEED_NOTE_HASH};

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
    fn tx(&self) -> &PoseidonParams<Self::F>;
    fn eddsa(&self) -> &PoseidonParams<Self::F>;
}

#[derive(Clone)]
pub struct PoolBN256<J:JubJubParams<Fr=Fr>, IN:Unsigned, OUT:Unsigned, H:Unsigned>{
    pub jubjub:J,
    pub hash: PoseidonParams<Fr>,
    pub compress: PoseidonParams<Fr>,
    pub note: PoseidonParams<Fr>,
    pub tx: PoseidonParams<Fr>,
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

    fn tx(&self) -> &PoseidonParams<Self::F> {
        &self.tx
    }

    fn eddsa(&self) -> &PoseidonParams<Self::F> {
        &self.eddsa
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct Note<F:Field> {
    pub d: Num<F>,
    pub pk_d: Num<F>,
    pub v: Num<F>,
    pub st: Num<F>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct Tx<P:PoolParams> {
    pub input: SizedVec<Note<P::F>, P::IN>,
    pub output: SizedVec<Note<P::F>, P::OUT>
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct TransferPub<P:PoolParams> {
    pub root: Num<P::F>,
    pub nullifier: SizedVec<Num<P::F>, P::IN>,
    pub out_hash: SizedVec<Num<P::F>, P::OUT>,
    pub delta: Num<P::F>,
    pub memo: Num<P::F>
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct TransferSec<P:PoolParams> {
    pub tx: Tx<P>,
    pub in_proof: SizedVec<MerkleProof<P::F,P::H>, P::IN>,
    pub eddsa_s: Num<P::F>,
    pub eddsa_r: Num<P::F>,
    pub eddsa_a: Num<P::F>
} 



pub fn nullfifier<P:PoolParams>(note_hash:Num<P::F>, pk:Num<P::F>, params:&P) -> Num<P::F>{
    poseidon_with_salt(&[note_hash, pk], SEED_NULLIFIER, params.compress())
}

pub fn note_hash<P:PoolParams>(note: Note<P::F>, params: &P) -> Num<P::F> {
    poseidon_with_salt(&[note.d, note.pk_d, note.v, note.st], SEED_NOTE_HASH, params.note())
}

pub fn tx_hash<P:PoolParams>(in_note_hash: &[Num<P::F>], out_note_hash: &[Num<P::F>], params:&P) -> Num<P::F> {
    let notes = in_note_hash.iter().chain(out_note_hash.iter()).cloned().collect::<Vec<_>>();
    poseidon_with_salt(&notes, SEED_TX_HASH, params.tx())
}

pub fn tx_sign<P:PoolParams>(sk: Num<<P::J as JubJubParams>::Fs>, tx_hash:Num<P::F>, params:&P) -> (Num<<P::J as JubJubParams>::Fs>, Num<P::F>) {
    eddsaposeidon_sign(sk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn tx_verify<P:PoolParams>(s:Num<<P::J as JubJubParams>::Fs>, r:Num<P::F>, pk: Num<P::F>, tx_hash:Num<P::F>, params:&P) -> bool {
    eddsaposeidon_verify(s, r, pk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn derive_key_pk<P:PoolParams>(sk:Num<<P::J as JubJubParams>::Fs>, params:&P) -> Num<P::F> {
    params.jubjub().edwards_g().mul(sk, params.jubjub()).x
}

pub fn derive_key_dk<P:PoolParams>(pk:Num<P::F>, params:&P) -> Num<<P::J as JubJubParams>::Fs> {
    let t_dk = poseidon_with_salt(&[pk], SEED_DECRYPTION_KEY, params.hash());
    t_dk.into_other::<<P::J as JubJubParams>::Fs>().into_other()
}

pub fn derive_key_pk_d<P:PoolParams>(d:Num<P::F>, dk:Num<<P::J as JubJubParams>::Fs>, params:&P) -> Num<P::F> {
    let d_hash = poseidon_with_salt(&[d], SEED_DIVERSIFIER, params.hash());
    EdwardsPoint::from_scalar(d_hash, params.jubjub()).mul(dk, params.jubjub()).x
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
