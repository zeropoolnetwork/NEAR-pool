use std::cell::RefCell;

use getrandom::getrandom;
use wasm_bindgen::prelude::*;

pub use rand::*;

thread_local! {
    pub static RNG: RefCell<CustomRng> = RefCell::new(CustomRng::default());
}

#[wasm_bindgen]
#[derive(Default)]
pub struct CustomRng;

impl Rng for CustomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        getrandom(&mut buf).expect("getrandom failed");

        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        getrandom(&mut buf).expect("getrandom failed");

        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom(dest).expect("getrandom failed");
    }
}
