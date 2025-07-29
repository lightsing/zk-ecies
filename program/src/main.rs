
use ecies_lib::*;
use std::hint::black_box;
use openvm_k256::Secp256k1Point;

openvm::entry!(main);
openvm::init!();

fn main() {
    let repetitions = openvm::io::read::<u32>();
    let exec_mode = openvm::io::read::<ExecMode>();

    let sk = openvm::io::read_vec();
    let sk = SecretKey::from_slice(&sk).unwrap();
    let ciphertext = openvm::io::read_vec();
    let ciphertext: &Message = ciphertext.as_slice().try_into().unwrap();
    let address = decrypt(&sk, ciphertext);

    if exec_mode == ExecMode::All {
        for _ in 0..repetitions {
            black_box(decrypt(black_box(&sk), black_box(ciphertext)));
        }
    }

    let mut out: [u8; 32] = [0u8; 32];
    out[..20].copy_from_slice(&address);
    openvm::io::reveal_bytes32(out);
}
