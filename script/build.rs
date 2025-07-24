use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs {
            #[cfg(feature = "profiling")]
            features: vec!["profiling".to_string()],
            ..Default::default()
        }
    )
}
