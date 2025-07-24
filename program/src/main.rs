#![no_main]

use ecies_lib::*;
use std::hint::black_box;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let repetitions = sp1_zkvm::io::read::<u32>();
    let exec_mode = sp1_zkvm::io::read::<ExecMode>();

    let sk = sp1_zkvm::io::read_vec();
    let sk = SecretKey::from_slice(&sk).unwrap();
    let ciphertext = sp1_zkvm::io::read_vec();
    let ciphertext: &Message = ciphertext.as_slice().try_into().unwrap();
    let address = decrypt(&sk, ciphertext);

    #[cfg(not(feature = "profiling"))]
    {
        if exec_mode == ExecMode::All {
            for _ in 0..repetitions {
                black_box(decrypt(black_box(&sk), black_box(ciphertext)));
            }
        }

        sp1_zkvm::io::commit_slice(&address);
    }
}
