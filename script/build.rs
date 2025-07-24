use sp1_build::{BuildArgs, build_program_with_args};

fn main() {
    build_program_with_args(
        "../program",
        BuildArgs {
            #[cfg(feature = "profiling")]
            features: vec!["profiling".to_string()],
            ..Default::default()
        },
    )
}
