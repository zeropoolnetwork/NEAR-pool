use ff_uint::{construct_uint, Uint};
use ff_uint::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::env;

construct_uint! {
    pub struct U256(4);
}

pub type G1 = [U256;2];
pub type G2 = [U256;4];

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct VK {
    alpha:G1,
    beta:G2,
    gamma:G2,
    delta:G2,
    ic: Vec<G1>
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Proof {
    a:G1,
    b:G2,
    c:G1
}

#[inline]
pub fn alt_bn128_g1_multiexp(v:&[(G1, U256)]) -> G1{
    let data = v.try_to_vec().unwrap_or_else(|_| env::panic(b"Cannot serialize data."));
    let res = env::alt_bn128_g1_multiexp(&data);
    let mut res_ptr = &res[..];
    <G1 as BorshDeserialize>::deserialize(&mut res_ptr).unwrap_or_else(|_| env::panic(b"Cannot deserialize data."))
}

#[inline]
pub fn alt_bn128_g1_sum(v:&[(bool, G1)]) -> G1{
    let data = v.try_to_vec().unwrap_or_else(|_| env::panic(b"Cannot serialize data."));
    let res = env::alt_bn128_g1_sum(&data);
    let mut res_ptr = &res[..];
    <G1 as BorshDeserialize>::deserialize(&mut res_ptr).unwrap_or_else(|_| env::panic(b"Cannot deserialize data."))
}

#[inline]
pub fn alt_bn128_g1_neg(p:G1) -> G1 {
    alt_bn128_g1_sum(&[(true, p)])
}

#[inline]
pub fn alt_bn128_pairing_check(v:&[(G1,G2)]) -> bool {
    let data = v.try_to_vec().unwrap_or_else(|_| env::panic(b"Cannot serialize data."));
    env::alt_bn128_pairing_check(&data)
}



pub fn alt_bn128_groth16verify(vk:&VK, proof:&Proof, input:&[U256]) -> bool {
    if vk.ic.len() != input.len() + 1 {
        env::panic(b"Wrong input len.");
    }
    let neg_a = alt_bn128_g1_neg(proof.a);
    let acc_expr = vk.ic.iter().zip([U256::ONE].iter().chain(input.iter())).map(|(&base, &exp)| (base, exp)).collect::<Vec<_>>();
    let acc = alt_bn128_g1_multiexp(&acc_expr);

    let pairing_expr = vec![
        (neg_a, proof.b),
        (vk.alpha, vk.beta),
        (acc, vk.gamma),
        (proof.c, vk.delta),
    ];

    alt_bn128_pairing_check(&pairing_expr)
    
}
