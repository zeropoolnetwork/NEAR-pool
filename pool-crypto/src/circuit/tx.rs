use typenum::Unsigned;

use fawkes_crypto::core::{signal::Signal, cs::ConstraintSystem, field::PrimeField, sizedvec::SizedVec};
use fawkes_crypto::circuit::{
    num::CNum, bool::CBool,
    poseidon::{c_poseidon_with_salt, c_poseidon_merkle_proof_root, CMerkleProof},
    eddsaposeidon::{c_eddsaposeidon_verify},
    ecc::CEdwardsPoint,
    bitify::{c_comp_constant, c_into_bits_le, c_into_bits_le_strict}
};
use fawkes_crypto::native::{num::Num, ecc::JubJubParams};

use num::bigint::{BigUint};
use num::One;


use crate::native::tx::{PoolParams, Note, TransferPub, TransferSec, Tx, NOTE_CHUNKS};
use crate::constants::{SEED_DIVERSIFIER, SEED_DECRYPTION_KEY, SEED_TX_HASH, SEED_NULLIFIER, SEED_NOTE_HASH};

#[derive(Clone, Signal)]
#[Value="Note<CS::F>"]
pub struct CNote<'a, CS:ConstraintSystem> {
    pub d: CNum<'a, CS>,
    pub pk_d: CNum<'a, CS>,
    pub v: CNum<'a, CS>,
    pub st: CNum<'a, CS>
}


#[derive(Clone, Signal)]
#[Value="TransferPub<P>"]
pub struct CTransferPub<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>> {
    pub root: CNum<'a, CS>,
    pub nullifier: SizedVec<CNum<'a, CS>, P::IN>,
    pub out_hash: SizedVec<CNum<'a, CS>, P::OUT>,
    pub delta: CNum<'a, CS>,
    pub memo: CNum<'a, CS>
}

#[derive(Clone, Signal)]
#[Value="Tx<P>"]
pub struct CTx<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>{
    pub input: SizedVec<CNote<'a, CS>, P::IN>,
    pub output: SizedVec<CNote<'a, CS>, P::OUT>
}


#[derive(Clone, Signal)]
#[Value="TransferSec<P>"]
pub struct CTransferSec<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>> {
    pub tx: CTx<'a, CS, P>,
    pub in_proof: SizedVec<CMerkleProof<'a, CS, P::H>, P::IN>,
    pub eddsa_s: CNum<'a, CS>,
    pub eddsa_r: CNum<'a, CS>,
    pub eddsa_a: CNum<'a, CS>
} 


pub fn c_nullfifier<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    note_hash:&CNum<'a, CS>,
    pk:&CNum<'a, CS>,
    params:&P,
) -> CNum<'a, CS>{
    c_poseidon_with_salt([note_hash.clone(), pk.clone()].as_ref(), SEED_NULLIFIER, params.compress())
}

pub fn c_note_hash<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    note: &CNote<'a, CS>,
    params: &P
) -> CNum<'a, CS> {
    c_poseidon_with_salt([note.d.clone(), note.pk_d.clone(), note.v.clone(), note.st.clone()].as_ref(), SEED_NOTE_HASH, params.note())
}

pub fn c_tx_hash<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    in_note_hash: &[CNum<'a, CS>],
    out_note_hash: &[CNum<'a, CS>],
    params:&P
) -> CNum<'a, CS> {
    let notes = in_note_hash.iter().chain(out_note_hash.iter()).cloned().collect::<Vec<_>>();
    c_poseidon_with_salt(&notes, SEED_TX_HASH, params.tx())
}


pub fn c_tx_verify<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    s:&CNum<'a, CS>, r:&CNum<'a, CS>, pk: &CNum<'a, CS>, tx_hash:&CNum<'a, CS>, params:&P) -> CBool<'a, CS> {
    c_eddsaposeidon_verify(s, r, pk, tx_hash, params.eddsa(), params.jubjub())
}

pub fn c_derive_key_dk<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    pk:&CNum<'a, CS>, params:&P
) -> Vec<CBool<'a, CS>> {
    let cs = pk.get_cs();
    let t_dk = c_poseidon_with_salt(&[pk.clone()], SEED_DECRYPTION_KEY, params.hash());
    let dk_value = t_dk.get_value().map(|v| v.into_other::<<P::J as JubJubParams>::Fs>().into_other());
    let dk = CNum::alloc(cs, dk_value.as_ref());

    let g = CEdwardsPoint::from_const(cs, params.jubjub().edwards_g());

    let t_dk_bits = c_into_bits_le_strict(&t_dk);
    let dk_bits = c_into_bits_le(&dk, <P::J as JubJubParams>::Fs::NUM_BITS as usize);
    c_comp_constant(&dk_bits, Num::<<P::J as JubJubParams>::Fs>::from(-1).into_other()).assert_false();
    (g.mul(&t_dk_bits, params.jubjub()).x - g.mul(&dk_bits, params.jubjub()).x).assert_zero();

    dk_bits
}

pub fn c_derive_key_pk_d<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(d:&CNum<'a, CS>, dk:&[CBool<'a, CS>], params:&P) -> CNum<'a, CS> {
    let d_hash = c_poseidon_with_salt(&[d.clone()], SEED_DIVERSIFIER, params.hash());
    CEdwardsPoint::from_scalar(&d_hash, params.jubjub()).mul(dk, params.jubjub()).x
}


pub fn c_parse_delta<'a, CS:ConstraintSystem>(
    delta:&CNum<'a, CS>
) -> CNum<'a, CS> {
    let delta_bits = c_into_bits_le(delta, 64);
    delta - &delta_bits[63].0 * num!(BigUint::one() << (NOTE_CHUNKS[2]*8))
}


pub fn c_transfer<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    p: &CTransferPub<'a, CS, P>,
    s: &CTransferSec<'a, CS, P>,
    params: &P)
{
    let cs = p.get_cs();

    //check note value ranges
    for n in s.tx.input.iter().chain(s.tx.output.iter()) {
        c_into_bits_le(&n.d, NOTE_CHUNKS[0]*8);
        c_into_bits_le(&n.v, NOTE_CHUNKS[2]*8);
        c_into_bits_le(&n.st, NOTE_CHUNKS[3]*8);
    }

    //build input hashes
    let in_hash = s.tx.input.iter().map(|n| c_note_hash(n, params)).collect::<Vec<_>>();

    //check decryption key
    let dk_bits = c_derive_key_dk(&s.eddsa_a, params);

    //build input ownership
    for i in 0..P::IN::USIZE {
        (&s.tx.input[i].pk_d - c_derive_key_pk_d(&s.tx.input[i].d, &dk_bits, params)).assert_zero(); 
    }

    //check nullifier
    for i in 0..P::IN::USIZE {
        (&p.nullifier[i]-c_nullfifier(&in_hash[i], &s.eddsa_a, params)).assert_zero();
    }

    //check nullifier unique
    let mut nullifier_unique_acc = CNum::from_const(cs, &Num::one());
    for i in 0..P::IN::USIZE {
        for j in i+1..P::IN::USIZE {
            nullifier_unique_acc *= &p.nullifier[i]-&p.nullifier[j];
        }
    }
    nullifier_unique_acc.assert_nonzero();


    //check output unique
    let mut output_unique_acc = CNum::from_const(cs, &Num::one());
    for i in 0..P::OUT::USIZE {
        for j in i+1..P::OUT::USIZE {
            output_unique_acc *= &p.out_hash[i]-&p.out_hash[j];
        }
    }
    output_unique_acc.assert_nonzero();


    //build output hashes
    for i in 0..P::OUT::USIZE {
        (&p.out_hash[i] - c_note_hash(&s.tx.output[i], params)).assert_zero();
    }

    //build merkle proofs
    for i in 0..P::IN::USIZE {
        let cur_root = c_poseidon_merkle_proof_root(&in_hash[i], &s.in_proof[i], params.compress());
        ((cur_root-&p.root)*&s.tx.input[i].v).assert_zero();
    }

    //bind msg_hash to the circuit
    (&p.memo+Num::one()).assert_nonzero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, &p.out_hash.0, params);

    //check signature
    c_tx_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params).assert_true();

    //parse delta    
    let delta_amount = c_parse_delta(&p.delta);

    //check balances
    let mut amount = delta_amount;

    for note in s.tx.input.iter() {
        amount += &note.v;
    }

    for note in s.tx.output.iter() {
        amount -= &note.v;
    }

    amount.assert_zero();
}


