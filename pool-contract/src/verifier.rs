use fawkes_crypto::borsh::{BorshDeserialize, BorshSerialize};
use serde::{Serialize, ser::{Serializer}, Deserialize, de::{Deserializer, self}};
use num::BigUint;
use core::str::FromStr;
use near_sdk::env;


#[derive(BorshDeserialize, BorshSerialize, Clone, Copy)]
pub struct Fr(pub [u8;32]);

pub const FR_ONE: Fr = Fr([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy)]
pub struct Fq(pub [u8;32]);



impl Serialize for Fr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let num = BigUint::from_bytes_le(&self.0[..]);
        serializer.serialize_str(&num.to_string())
    }
}

impl<'de> Deserialize<'de> for Fr {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        let num = BigUint::from_str(&s).map_err(|_| de::Error::custom("Wrong number format"))?;
        let data = num.to_bytes_le();
        if data.len() > 32 {
            Err(de::Error::custom("Too long number"))
        } else {
            let mut res = Self([0;32]);
            &mut res.0[..data.len()].clone_from_slice(&data);
            Ok(res)
        }
    }
}


impl Serialize for Fq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let num = BigUint::from_bytes_le(&self.0[..]);
        serializer.serialize_str(&num.to_string())
    }
}

impl<'de> Deserialize<'de> for Fq {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        let num = BigUint::from_str(&s).map_err(|_| de::Error::custom("Wrong number format"))?;
        let data = num.to_bytes_le();
        if data.len() > 32 {
            Err(de::Error::custom("Too long number"))
        } else {
            let mut res = Self([0;32]);
            &mut res.0[..data.len()].clone_from_slice(&data);
            Ok(res)
        }
    }
}


#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Serialize, Deserialize)]
pub struct Fq2(pub Fq, pub Fq);


#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Serialize, Deserialize)]
pub struct G1(pub Fq, pub Fq);
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Serialize, Deserialize)]
pub struct G2(pub Fq2, pub Fq2);


#[inline]
pub fn alt_bn128_g1_multiexp(v:Vec<(G1, Fr)>) -> G1{
    let data = v.try_to_vec().unwrap_or_else(|_| env::panic(b"Cannot serialize data."));
    let res = env::alt_bn128_g1_multiexp(&data);
    let mut res_ptr = &res[..];
    <G1 as BorshDeserialize>::deserialize(&mut res_ptr).unwrap_or_else(|_| env::panic(b"Cannot deserialize data."))
}

#[inline]
pub fn alt_bn128_g1_sum(v:Vec<(bool, G1)>) -> G1{
    let data = v.try_to_vec().unwrap_or_else(|_| env::panic(b"Cannot serialize data."));
    let res = env::alt_bn128_g1_sum(&data);
    let mut res_ptr = &res[..];
    <G1 as BorshDeserialize>::deserialize(&mut res_ptr).unwrap_or_else(|_| env::panic(b"Cannot deserialize data."))
}

#[inline]
pub fn alt_bn128_g1_neg(p:G1) -> G1 {
    alt_bn128_g1_sum(vec![(true, p)])
}

#[inline]
pub fn alt_bn128_pairing_check(v:Vec<(G1,G2)>) -> bool {
    let data = v.try_to_vec().unwrap_or_else(|_| env::panic(b"Cannot serialize data."));
    env::alt_bn128_pairing_check(&data)
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Serialize, Deserialize)]
pub struct VK {
    pub alpha_g1: G1,
    pub beta_g2: G2,
    pub gamma_g2: G2,
    pub delta_g2: G2,
    pub ic: Vec<G1>,
}


#[derive(BorshDeserialize, BorshSerialize, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}


pub fn alt_bn128_groth16verify(vk:VK, proof:Proof, input:Vec<Fr>) -> bool {
    if vk.ic.len() != input.len() + 1 {
        env::panic(b"Wrong input len.");
    }
    let neg_a = alt_bn128_g1_neg(proof.a);
    let acc_expr = vk.ic.iter().zip([FR_ONE].iter().chain(input.iter())).map(|(&base, &exp)| (base, exp)).collect::<Vec<_>>();
    let acc = alt_bn128_g1_multiexp(acc_expr);

    let pairing_expr = vec![
        (neg_a, proof.b),
        (vk.alpha_g1, vk.beta_g2),
        (acc, vk.gamma_g2),
        (proof.c, vk.delta_g2),
    ];

    alt_bn128_pairing_check(pairing_expr)
    
}


pub mod native {
    use super::*;
    use bn_borsh::{BorshSerialize as _, BorshDeserialize as _};
    use bn::{pairing_batch, Fr as _Fr, Group, Gt, G1 as _G1, G2 as _G2};

    fn alt_bn128_g1_multiexp(items: &[(G1, Fr)]) -> G1 {
        let ref items = <Vec<(_G1, _Fr)>>::try_from_slice(&items.to_vec().try_to_vec().unwrap()).unwrap();
        let res = _G1::multiexp(items);
        G1::try_from_slice(&res.try_to_vec().unwrap()).unwrap()
    }

    fn alt_bn128_g1_sum(items: &[(bool, G1)]) -> G1 {
        let ref items = <Vec<(bool, _G1)>>::try_from_slice(&items.to_vec().try_to_vec().unwrap()).unwrap();
        let mut acc = _G1::zero();
        for &(sign, e) in items.iter() {
            if sign {
                acc = acc - e;
            } else {
                acc = acc + e;
            }
        }
        let res = acc;
        G1::try_from_slice(&res.try_to_vec().unwrap()).unwrap()
    }

    #[inline]
    fn alt_bn128_g1_neg(p:G1) -> G1 {
        let res = alt_bn128_g1_sum(&vec![(true, p)]);
        G1::try_from_slice(&res.try_to_vec().unwrap()).unwrap()
    }

    fn alt_bn128_pairing_check(items: &[(G1, G2)]) -> bool {
        let ref items = <Vec<(_G1, _G2)>>::try_from_slice(&items.to_vec().try_to_vec().unwrap()).unwrap();
        pairing_batch(items) == Gt::one()
    }

    pub fn alt_bn128_groth16verify_native(vk:VK, proof:Proof, input:Vec<Fr>) -> bool {
        if vk.ic.len() != input.len() + 1 {
            env::panic(b"Wrong input len.");
        }
        let neg_a = alt_bn128_g1_neg(proof.a);
        let acc_expr = vk.ic.iter().zip([FR_ONE].iter().chain(input.iter())).map(|(&base, &exp)| (base, exp)).collect::<Vec<_>>();
        let acc = alt_bn128_g1_multiexp(&acc_expr);

        let pairing_expr = vec![
            (neg_a, proof.b),
            (vk.alpha_g1, vk.beta_g2),
            (acc, vk.gamma_g2),
            (proof.c, vk.delta_g2),
        ];

        alt_bn128_pairing_check(&pairing_expr)
        
    }
    

}