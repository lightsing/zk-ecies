#![no_main]

use ecies_lib::*;
use std::hint::black_box;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let repetitions = sp1_zkvm::io::read::<u32>();
    let exec_mode = sp1_zkvm::io::read::<ExecMode>();

    let sk = sp1_zkvm::io::read_vec();
    let ciphertext = sp1_zkvm::io::read_vec();
    let address = decrypt(sk.as_ref(), ciphertext.as_ref()).unwrap();

    if exec_mode == ExecMode::All {
        for _ in 0..repetitions {
            black_box(decrypt(
                black_box(sk.as_ref()),
                black_box(ciphertext.as_ref()),
            ))
            .unwrap();
        }
    }

    sp1_zkvm::io::commit(&address);
}
