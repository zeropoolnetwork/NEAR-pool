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



use crate::native::transfer::{PoolParams, Note, TxPub, TxSec};
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
#[Value="TxPub<P>"]
pub struct CTxPub<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>> {
    pub root: CNum<'a, CS>,
    pub nullifier: SizedVec<CNum<'a, CS>, P::IN>,
    pub out_hash: SizedVec<CNum<'a, CS>, P::OUT>,
    pub delta: CNum<'a, CS>,
    pub memo: CNum<'a, CS>
}




#[derive(Clone, Signal)]
#[Value="TxSec<P>"]
pub struct CTxSec<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>> {
    pub in_note: SizedVec<CNote<'a, CS>, P::IN>,
    pub out_note: SizedVec<CNote<'a, CS>, P::OUT>,
    pub in_proof: SizedVec<CMerkleProof<'a, CS, P::H>, P::IN>,
    pub dk: CNum<'a, CS>,
    pub eddsa_s: CNum<'a, CS>,
    pub eddsa_r: CNum<'a, CS>,
    pub eddsa_a: CNum<'a, CS>
} 


pub fn c_nullfifier<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    note_hash:&CNum<'a, CS>,
    dk:&CNum<'a, CS>,
    params:&P,
) -> CNum<'a, CS>{
    c_poseidon_with_salt([note_hash.clone(), dk.clone()].as_ref(), SEED_NULLIFIER, params.compress())
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
    c_poseidon_with_salt(&notes, SEED_TX_HASH, params.compress())
}

pub fn c_parse_delta<'a, CS:ConstraintSystem>(
    delta:&CNum<'a, CS>
) -> CNum<'a, CS> {
    let delta_bits = c_into_bits_le(delta, 128);
    delta - &delta_bits[127].0 * num!("340282366920938463463374607431768211456")
}


pub fn c_tx<'a, CS:ConstraintSystem, P:PoolParams<F=CS::F>>(
    p: &CTxPub<'a, CS, P>,
    s: &CTxSec<'a, CS, P>,
    params: &P)
{
    let cs = p.get_cs();

    //check note value ranges
    for n in s.in_note.iter().chain(s.out_note.iter()) {
        c_into_bits_le(&n.d, 80);
        c_into_bits_le(&n.v, 64);
        c_into_bits_le(&n.st, 80);
    }

    //build input hashes
    let in_hash = s.in_note.iter().map(|n| c_note_hash(n, params)).collect::<Vec<_>>();

    //check decryption key
    let dk_bits = c_into_bits_le(&s.dk, <P::J as JubJubParams>::Fs::NUM_BITS as usize);
    c_comp_constant(&dk_bits, Num::<<P::J as JubJubParams>::Fs>::from(-1).into_other()).assert_false();

    //build input ownership
    for i in 0..P::IN::USIZE {
        let d_hash = c_poseidon_with_salt(&[s.in_note[i].d.clone()], SEED_DIVERSIFIER, params.hash());
        let g_d = CEdwardsPoint::from_scalar(&d_hash, params.jubjub());
        (&s.in_note[i].pk_d - g_d.mul(&dk_bits, params.jubjub()).x).assert_zero();
    }

    //check nullifier
    for i in 0..P::IN::USIZE {
        (&p.nullifier[i]-c_nullfifier(&in_hash[i], &s.dk, params)).assert_zero();
    }

    //check nullifier unique
    let mut nullifier_unique_acc = CNum::from_const(cs, &Num::one());
    for i in 0..P::IN::USIZE {
        for j in i+1..P::IN::USIZE {
            nullifier_unique_acc *= &p.nullifier[i]-&p.nullifier[j];
        }
    }
    nullifier_unique_acc.assert_nonzero();

    //build output hashes
    for i in 0..P::OUT::USIZE {
        (&p.out_hash[i] - c_note_hash(&s.out_note[i], params)).assert_zero();
    }

    //build merkle proofs
    for i in 0..P::IN::USIZE {
        let cur_root = c_poseidon_merkle_proof_root(&in_hash[i], &s.in_proof[i], params.compress());
        ((cur_root-&p.root)*&s.in_note[i].v).assert_zero();
    }

    //bind msg_hash to the circuit
    (&p.memo+Num::one()).assert_nonzero();

    //build tx hash
    let tx_hash = c_tx_hash(&in_hash, &p.out_hash.0, params);

    //check signature
    (c_eddsaposeidon_verify(&s.eddsa_s, &s.eddsa_r, &s.eddsa_a, &tx_hash, params.eddsa(), params.jubjub()).0 - Num::one()).assert_zero();

    //check decryption key

    let g = CEdwardsPoint::from_const(cs, params.jubjub().edwards_g());
    let t_dk = c_poseidon_with_salt(&[s.eddsa_a.clone()].as_ref(), SEED_DECRYPTION_KEY, params.hash());
    let t_dk_bits = c_into_bits_le_strict(&t_dk);
    (g.mul(&t_dk_bits, params.jubjub()).x - g.mul(&dk_bits, params.jubjub()).x).assert_zero();

    //parse delta    
    let delta_amount = c_parse_delta(&p.delta);

    //check balances
    let mut amount = delta_amount;

    for note in s.in_note.iter() {
        amount += &note.v;
    }

    for note in s.out_note.iter() {
        amount -= &note.v;
    }

    amount.assert_zero();
}


