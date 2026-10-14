//! Embeds the daemon's Info.plist in the `agentsweepd` binary.
//!
//! The daemon's signing identifier is frozen as `de.byte5.agentsweep.daemon`,
//! because the Keychain key behind the Event Log is bound to it (spec section
//! 9.1). Tauri signs each sidecar without naming an identifier, and codesign
//! then takes the bundle identifier of an Info.plist embedded in the binary's
//! `__TEXT,__info_plist` section, or the file name when there is none. The
//! linker puts the plist beside this script into that section, so Tauri's own
//! signing yields the frozen identifier and nothing re-signs after it. Only the
//! daemon binary carries it; the library and the tests do not.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("a manifest dir"));
    let plist = manifest_dir.join("Info.plist");
    println!("cargo::rerun-if-changed={}", plist.display());

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!(
            "cargo::rustc-link-arg-bin=agentsweepd=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            plist.display()
        );
    }
}
