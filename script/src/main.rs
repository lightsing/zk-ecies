use ecies_lib::{utils::generate_keypair, *};
use sp1_sdk::{CpuProver, Prover, SP1Stdin, include_elf};
use std::env;

pub const ELF: &[u8] = include_elf!("ecies-program");

fn main() {
    sp1_sdk::utils::setup_logger();

    let client = CpuProver::new();
    let (proving_key, verifying_key) = client.setup(ELF);

    let repetitions = 1000;

    let (secret_key, public_key) = generate_keypair();
    let address: [u8; 20] = rand::random();
    let ciphertext = encrypt(&public_key.serialize(), &address).unwrap();
    println!("[+] encrypted address length: {}", ciphertext.len());

    println!("[+] Running decrypt:");

    if cfg!(feature = "profiling") {
        env::set_var("TRACE_FILE", format!("decrypt-{repetitions}.json"));
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&repetitions);
    stdin.write(&ExecMode::All);
    stdin.write_slice(secret_key.as_ref());
    stdin.write_slice(&ciphertext);

    let (mut public_values, report) = client.execute(&ELF, &stdin).run().unwrap();
    let total_instruction_count = report.total_instruction_count();
    println!("- Total Instructions: {total_instruction_count}");
    let decrypted: Vec<u8> = public_values.read();
    assert_eq!(decrypted, address);

    if !cfg!(feature = "profiling") {
        let now = std::time::Instant::now();
        let proof = client
            .prove(&proving_key, &stdin)
            .compressed()
            .run()
            .unwrap();
        let total_proving_time = now.elapsed();
        // sanity check
        client.verify(&proof, &verifying_key).unwrap();

        // run baseline
        let mut stdin = SP1Stdin::new();
        stdin.write(&repetitions);
        stdin.write(&ExecMode::Baseline);
        stdin.write_slice(secret_key.as_ref());
        stdin.write_slice(&ciphertext);
        let (_, report) = client.execute(&ELF, &stdin).run().unwrap();
        let baseline_instruction_count = report.total_instruction_count();
        let net_instruction_count = total_instruction_count - baseline_instruction_count;
        let net_instruction_per_operation = net_instruction_count as f64 / repetitions as f64;

        let now = std::time::Instant::now();
        let proof = client
            .prove(&proving_key, &stdin)
            .compressed()
            .run()
            .unwrap();
        let baseline_proving_time = now.elapsed();
        let net_proving_time = total_proving_time - baseline_proving_time;
        let net_proving_time_per_operation = net_proving_time / repetitions;

        // sanity check
        client.verify(&proof, &verifying_key).unwrap();

        println!("- Total Proving Time: {total_proving_time:?}");
        println!("- Baseline Instructions: {baseline_instruction_count}");
        println!("- Baseline Proving Time: {baseline_proving_time:?}");
        println!("- Net Instructions: {net_instruction_count}");
        println!("- Net Proving Time: {net_proving_time:?}");
        println!("- Net Instructions per operation: {net_instruction_per_operation:.2}");
        println!("- Net Proving Time per operation: {net_proving_time_per_operation:?}");
    }
}
