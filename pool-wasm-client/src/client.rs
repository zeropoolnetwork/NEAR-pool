use std::ops::DerefMut;
use std::str::FromStr;

use fawkes_crypto::native::num::Num;
use num::{BigInt, BigUint};
use pool_circuit::native::data::{ClientState as InnerClientState, NativeWallet};
use pool_circuit::native::tx::{
    derive_key_pk_d, note_hash, Note as InnerNote, PoolParams, TransferPub, TransferSec,
};
use pool_circuit::{TPoolParams, POOL_PARAMS};
use rand::Rng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::database::{Database, KvdbDatabase};
use crate::random::RNG;

#[wasm_bindgen]
pub struct ClientState {
    client: InnerClientState<
        'static,
        'static,
        'static,
        TPoolParams,
        KvdbDatabase,
        NativeWallet<TPoolParams>,
    >,
}

#[wasm_bindgen]
impl ClientState {
    pub fn new(db: &Database, wallet: &Wallet) -> ClientState {
        // FIXME: Temporary: adapt the API for the concrete use case instead of using unsafe lifetime coercion.
        let (db, wallet) = unsafe {
            (
                std::mem::transmute::<_, &'static KvdbDatabase>(&db.inner),
                std::mem::transmute::<_, &'static NativeWallet<TPoolParams>>(&wallet.inner),
            )
        };
        let client = InnerClientState::new(db, wallet, &POOL_PARAMS);

        ClientState { client }
    }

    pub fn total_balance(&self) -> String {
        let balance = self.client.total_balance();
        format!("{:?}", balance)
    }

    pub fn add_leaf(&self, note_hash: &str, note: Option<Note>) -> Result<(), JsValue> {
        let hash = <<TPoolParams as PoolParams>::Fr>::from_hex(note_hash)
            .map_err(|err| format!("{}", err))?;
        let note = note.map(|n| n.inner.clone());
        self.client.add_leaf(Num(hash), note);

        Ok(())
    }

    /// `recv_addr` must be an array of 2 strings that represent hex encoded numbers.
    /// `amount` and `delta` must be strings of digits with radix 10.
    pub fn make_transaction_object(
        &self,
        recv_addr: JsValue,
        amount: String,
        delta: String,
    ) -> Result<Option<TransactionObject>, JsValue> {
        RNG.with(|rng| {
            let mut rng = rng.borrow_mut();

            let recv_addr: RecvAddr = recv_addr.into_serde().map_err(|err| format!("{}", err))?;
            let recv_addr = {
                (
                    Num(<<TPoolParams as PoolParams>::Fr>::from_hex(&recv_addr.0[0])
                        .map_err(|err| format!("{}", err))?),
                    Num(<<TPoolParams as PoolParams>::Fr>::from_hex(&recv_addr.0[1])
                        .map_err(|err| format!("{}", err))?),
                )
            };

            let amount = BigUint::from_str(&amount).map_err(|err| format!("{}", err))?;
            let delta = BigInt::from_str(&delta).map_err(|err| format!("{}", err))?;

            let obj = self
                .client
                .make_transaction_object(rng.deref_mut(), recv_addr, amount, delta)
                .map(|(transfer_pub, transfer_sec, assets)| TransactionObject {
                    transfer_pub,
                    transfer_sec,
                    assets,
                });

            Ok(obj)
        })
    }

    pub fn get_note_list(&self) -> js_sys::Array {
        self.client
            .get_note_list()
            .into_iter()
            .map(|(_, note)| {
                // TODO: Is the first element of the tuple needed?
                let note = Note { inner: note };
                JsValue::from_serde(&note).unwrap()
            })
            .collect()
    }
}

#[derive(Deserialize)]
struct RecvAddr([String; 2]);

#[wasm_bindgen]
pub struct TransactionObject {
    transfer_pub: TransferPub<TPoolParams>,
    transfer_sec: TransferSec<TPoolParams>,
    assets: Vec<u8>,
}

#[wasm_bindgen]
pub struct Wallet {
    inner: NativeWallet<TPoolParams>,
}

#[wasm_bindgen]
impl Wallet {
    pub fn new(sk: String) -> Result<Wallet, JsValue> {
        let sk =
            Num(<<TPoolParams as PoolParams>::Fs>::from_hex(&sk)
                .map_err(|err| format!("{}", err))?);

        Ok(Wallet {
            inner: NativeWallet { sk },
        })
    }
}

#[wasm_bindgen]
#[derive(Deserialize, Serialize)]
pub struct Note {
    #[serde(flatten)]
    inner: InnerNote<<TPoolParams as PoolParams>::Fr>,
}

#[wasm_bindgen]
impl Note {
    pub fn new(state: &ClientState) -> Note {
        // FIXME: How to properly initialize a note without rng?
        let mut inner: InnerNote<<TPoolParams as PoolParams>::Fr> =
            RNG.with(|rng| rng.borrow_mut().gen());
        inner.pk_d = derive_key_pk_d(inner.d, state.client.dk, &*POOL_PARAMS).x;

        Note { inner }
    }

    pub fn hash(&self) -> String {
        let hash = note_hash(self.inner.clone(), &*POOL_PARAMS);
        hash.0.to_hex()
    }
}
