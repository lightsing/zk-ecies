use serde::{Deserialize, Serialize};

pub use ecies::*;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecMode {
    Baseline,
    All,
}
