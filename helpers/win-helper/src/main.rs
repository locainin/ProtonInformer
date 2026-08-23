//! Windows-side helper executable entry point

#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic, clippy::nursery)]

use std::process::ExitCode;

fn main() -> ExitCode {
    proton_informer_win_helper::main_entry()
}
