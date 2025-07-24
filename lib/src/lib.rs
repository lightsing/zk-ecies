use serde::{Deserialize, Serialize};

pub use ecies::*;
pub use k256::elliptic_curve;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecMode {
    Baseline,
    All,
}
