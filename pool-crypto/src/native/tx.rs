use fawkes_crypto::native::{
    num::Num, ecc::{JubJubParams, EdwardsPoint},
    poseidon::{PoseidonParams, MerkleProof, poseidon_with_salt},
    eddsaposeidon::{eddsaposeidon_sign, eddsaposeidon_verify}
};

use fawkes_crypto::core::{
    sizedvec::SizedVec,
    field::{Field, PrimeField}
};
use num::bigint::{BigUint, BigInt};
use num::bigint::Sign;

use num::{One, Zero};
use typenum::Unsigned;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::io::{Cursor, Write, self};
use crate::constants::{SEED_DIVERSIFIER, SEED_DECRYPTION_KEY, SEED_TX_HASH, SEED_NULLIFIER, SEED_NOTE_HASH};


use fawkes_crypto::native::bn256::{Fr, JubJubBN256};
use fawkes_crypto::borsh::{BorshSerialize, BorshDeserialize};
use sha3::{Digest, Keccak256};

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
pub struct PoolBN256<IN:Unsigned, OUT:Unsigned, H:Unsigned>{
    pub jubjub:JubJubBN256,
    pub hash: PoseidonParams<Fr>,
    pub compress: PoseidonParams<Fr>,
    pub note: PoseidonParams<Fr>,
    pub tx: PoseidonParams<Fr>,
    pub eddsa: PoseidonParams<Fr>,
    pub phantom: PhantomData<(IN, OUT, H)>
}

impl<IN:Unsigned, OUT:Unsigned, H:Unsigned> PoolParams for PoolBN256<IN, OUT, H> {
    type F = Fr;
    type J = JubJubBN256;
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


pub const NOTE_CHUNKS: [usize;4] = [10, 32, 8, 10];

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct Note<F:Field> {
    pub d: Num<F>,
    pub pk_d: Num<F>,
    pub v: Num<F>,
    pub st: Num<F>
}


fn to_compressed(buf: &[u8], num_size:usize, chunks: &[usize]) -> Result<Vec<u8>, io::Error> {
    let buf_len = buf.len();
    let chunks_len = chunks.len();
    if buf_len % num_size != 0 || buf_len / num_size != chunks_len {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong length of elements"))
    } else {
        let mut cur = Cursor::new(vec![]);
        for (i, c) in chunks.iter().enumerate() {
            if buf[num_size*i+c..num_size*i+num_size].iter().any(|&e| e!=0) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong serialization"))
            }
            cur.write(&buf[num_size*i..num_size*i+c])?;
        }
        Ok(cur.into_inner())
    }
}

fn to_decompressed(buf: &[u8], num_size:usize, chunks: &[usize]) -> Result<Vec<u8>, io::Error> {
    let buf_len = buf.len();
    let chunks_len = chunks.len();
    if buf_len != chunks.iter().sum::<usize>() {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong length of elements"))
    } else {
        let mut res = vec![0; num_size*chunks_len];
        let mut cur = 0;
        for (i, c) in chunks.iter().enumerate() {
            res[num_size*i..num_size*i+c].clone_from_slice(&buf[cur..cur+c]);
            cur+=c;
        }
        Ok(res)
    }
}


impl<T:Field> BorshSerialize for Note<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        let num_size = (T::NUM_BITS as usize-1)/8+1;
        let mut cur = Cursor::new(vec![]);
        self.d.serialize(&mut cur)?;
        self.pk_d.serialize(&mut cur)?;
        self.v.serialize(&mut cur)?;
        self.st.serialize(&mut cur)?;
        let buf = cur.into_inner();
        writer.write(&to_compressed(&buf, num_size, &NOTE_CHUNKS)?)?;
        Ok(())
    }
}

impl<T:Field> BorshDeserialize for Note<T> {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, io::Error> {
        let num_size = (T::NUM_BITS as usize-1)/8+1;
        let note_size = NOTE_CHUNKS.iter().sum();
        if buf.len() < note_size {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Too short data"))
        } else {
            let data = to_decompressed(&buf[0..note_size], num_size, &NOTE_CHUNKS)?;
            *buf = &buf[note_size..];
            let mut r = &data[..];
            Ok(Self{
                d: Num::deserialize(&mut r)?,
                pk_d: Num::deserialize(&mut r)?,
                v: Num::deserialize(&mut r)?,
                st: Num::deserialize(&mut r)?
            })
        }
    }
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

fn xor_crypt<D:Digest+Clone>(prefix:&D, data:&[u8]) -> Vec<u8> {
    let mut mask = vec![];
    
    for i in 0.. (data.len()-1)/32+1 {
        let mut m = prefix.clone();
        m.update([i as u8]);
        mask.extend(m.finalize());
    }
    data.iter().zip(mask.iter()).map(|(&d, &m)| d^m).collect()
}

fn dh_prefix<F:Field>(dh_x: Num<F>, h:&[u8]) -> Keccak256 {
    let mut res = Keccak256::new();
    res.update(dh_x.try_to_vec().unwrap());
    res.update(h);
    res
}


pub fn note_encrypt<P:PoolParams>(esk: Num<<P::J as JubJubParams>::Fs>, dk: Num<<P::J as JubJubParams>::Fs>, note: Note<P::F>, params: &P) -> Vec<u8> {
    let pk_d = EdwardsPoint::subgroup_decompress(note.pk_d, params.jubjub()).unwrap();
    let dh = pk_d.mul(esk, params.jubjub());

    let note_vec = note.try_to_vec().unwrap();

    let mut hasher = Keccak256::new();
    hasher.update(&note_vec);
    let note_hash = hasher.finalize();
    

    let note_vec_enc = xor_crypt(&dh_prefix(dh.x, &note_hash), &note_vec);

    let epk = derive_key_pk_d(note.d, esk, params);
    let epk2 = dh.mul(dk.inverse(), params.jubjub());

    let mut res = vec![];

    res.extend(epk.x.try_to_vec().unwrap());
    res.extend(epk2.x.try_to_vec().unwrap());
    res.extend(note_hash);
    res.extend(note_vec_enc);
    res
}

fn note_decrypt<P:PoolParams>(dk: Num<<P::J as JubJubParams>::Fs>, epk:Num<P::F>, note_data:&[u8], params: &P) -> Option<Note<P::F>> {
    let epk = EdwardsPoint::subgroup_decompress(epk, params.jubjub())?;
    let dh = epk.mul(dk, params.jubjub());

    let prefix = dh_prefix(dh.x, &note_data[..32]);
    let note_vec = xor_crypt(&prefix, &note_data[32..]);

    let mut hasher = Keccak256::new();
    hasher.update(&note_vec);
    let note_hash = hasher.finalize();

    if note_data[..32].iter().zip(note_hash.iter()).any(|(a,b)| a!=b) {
        None
    } else {
        Note::try_from_slice(&note_vec).ok()
    }
}

pub fn note_decrypt_in<P:PoolParams>(dk: Num<<P::J as JubJubParams>::Fs>, msg_data:&[u8], params: &P) -> Option<Note<P::F>> {
    let note_size: usize = NOTE_CHUNKS.iter().sum();
    let num_size = (P::F::NUM_BITS as usize-1)/8+1;
    if msg_data.len() != 32+2*num_size+note_size {
        None
    } else {
        let epk = Num::try_from_slice(&msg_data[0..num_size]).ok()?;
        note_decrypt(dk, epk, &msg_data[2*num_size..], params)
    }
}

pub fn note_decrypt_out<P:PoolParams>(dk: Num<<P::J as JubJubParams>::Fs>, msg_data:&[u8], params: &P) -> Option<Note<P::F>> {
    let note_size: usize = NOTE_CHUNKS.iter().sum();
    let num_size = (P::F::NUM_BITS as usize-1)/8+1;
    if msg_data.len() != 32+2*num_size+note_size {
        None
    } else {
        let epk = Num::try_from_slice(&msg_data[num_size..num_size*2]).ok()?;
        note_decrypt(dk, epk, &msg_data[2*num_size..], params)
    }
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

pub fn derive_key_pk<P:PoolParams>(sk:Num<<P::J as JubJubParams>::Fs>, params:&P) -> EdwardsPoint<P::F> {
    params.jubjub().edwards_g().mul(sk, params.jubjub())
}

pub fn derive_key_dk<P:PoolParams>(pk:Num<P::F>, params:&P) -> Num<<P::J as JubJubParams>::Fs> {
    let t_dk = poseidon_with_salt(&[pk], SEED_DECRYPTION_KEY, params.hash());
    t_dk.into_other::<<P::J as JubJubParams>::Fs>().into_other()
}

pub fn derive_key_pk_d<P:PoolParams>(d:Num<P::F>, dk:Num<<P::J as JubJubParams>::Fs>, params:&P) -> EdwardsPoint<P::F> {
    let d_hash = poseidon_with_salt(&[d], SEED_DIVERSIFIER, params.hash());
    EdwardsPoint::from_scalar(d_hash, params.jubjub()).mul(dk, params.jubjub())
}

pub fn parse_delta<F:Field>(delta:Num<F>) -> Num<F> {
    let delta_num = Into::<BigUint>::into(delta);
    let min_neg_amount =  BigUint::one() << (NOTE_CHUNKS[2]*8-1);
    let limit_amount = BigUint::one() << (NOTE_CHUNKS[2]*8);
    assert!(delta_num < limit_amount);

    if delta_num < min_neg_amount {
        delta
    } else {
        delta - num!(limit_amount)
    }
}



#[cfg(test)]
mod tx_test {
    use super::*;
    use rand::{Rand, Rng, thread_rng};
    use num::BigUint;
    use fawkes_crypto::native::bn256::{Fr};
    use crate::POOL_PARAMS;
    use crate::native::data::rand_biguint;



    impl Rand for Note<Fr> {
        fn rand<R: Rng>(rng: &mut R) -> Self {
            Self {
                d: num!(rand_biguint(rng, NOTE_CHUNKS[0]*8)),
                pk_d: num!(rand_biguint(rng, NOTE_CHUNKS[1]*8)),
                v: num!(rand_biguint(rng, NOTE_CHUNKS[2]*8)),
                st: num!(rand_biguint(rng, NOTE_CHUNKS[3]*8))
            }
        }
    }


    #[test]
    fn test_encryption() {
        let mut rng = thread_rng();
        let esk = rng.gen();
        let dk = rng.gen();

        let mut note:Note<Fr> = rng.gen();
        
        let r_dk = rng.gen();
        let r_pk_d = derive_key_pk_d(note.d, r_dk, &*POOL_PARAMS).x;
        note.pk_d = r_pk_d;

        
        let msg = note_encrypt(esk, dk, note, &*POOL_PARAMS);
        let note1 = note_decrypt_out(dk, &msg, &*POOL_PARAMS).unwrap();
        let note2 = note_decrypt_in(r_dk, &msg, &*POOL_PARAMS).unwrap();

        assert!(note == note1, "Decryption for sender should be correct");
        assert!(note == note2, "Decryption for receiver should be correct");
        

    }
}