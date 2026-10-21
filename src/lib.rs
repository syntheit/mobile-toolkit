//! mobile-toolkit: Qualcomm EDL (Sahara + Firehose) recovery tooling.

/// `println!` that never panics: once stdout is gone (EPIPE from `mtk ... | head`)
/// output is dropped and the command carries on, so a closed pipe can never
/// abort a write halfway. Shadows std's macro in this crate; main.rs imports it.
#[macro_export]
macro_rules! println {
    () => { $crate::emit(false, format_args!("\n")) };
    ($($t:tt)*) => { $crate::emit(false, format_args!("{}\n", format_args!($($t)*))) };
}

/// `eprintln!` that never panics (see `println!`).
#[macro_export]
macro_rules! eprintln {
    () => { $crate::emit(true, format_args!("\n")) };
    ($($t:tt)*) => { $crate::emit(true, format_args!("{}\n", format_args!($($t)*))) };
}

/// `eprint!` that never panics (see `println!`).
#[macro_export]
macro_rules! eprint {
    ($($t:tt)*) => { $crate::emit(true, format_args!($($t)*)) };
}

#[doc(hidden)]
pub fn emit(stderr: bool, args: std::fmt::Arguments) {
    use std::io::Write;
    let _ = if stderr {
        std::io::stderr().write_fmt(args)
    } else {
        std::io::stdout().write_fmt(args)
    };
}

pub mod devinfo;
pub mod firehose;
pub mod gpt;
pub mod image;
pub mod ops;
pub mod profile;
pub mod sahara;
pub mod slot;
pub mod usb;
pub mod write;
