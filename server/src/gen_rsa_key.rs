// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use rsa::{pkcs1::EncodeRsaPrivateKey, RsaPrivateKey};

fn main() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new_with_exp(&mut rng, 2048, &65537u32.into()).unwrap();
    priv_key
        .write_pkcs1_pem_file("privkey.pem", rsa::pkcs8::LineEnding::LF)
        .unwrap()
}
