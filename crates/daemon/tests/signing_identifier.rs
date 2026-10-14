//! The daemon's signing identifier is frozen as `de.byte5.agentsweep.daemon`,
//! because the Keychain key behind the Event Log is bound to it (spec section
//! 9.1). The daemon binary carries an Info.plist in its `__TEXT,__info_plist`
//! section whose bundle identifier is the frozen one, so a signature made
//! without an explicit identifier, which is how Tauri signs its sidecars,
//! takes the frozen identifier rather than the file name.

use std::fs;
use std::path::Path;
use std::process::Command;

const EMBEDDED_PLIST: &[u8] = include_bytes!("../Info.plist");

fn daemon_binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_agentsweepd"))
}

#[test]
fn the_embedded_info_plist_names_the_frozen_identifier() {
    let plist = std::str::from_utf8(EMBEDDED_PLIST).expect("a UTF-8 plist");
    let expected = format!(
        "<key>CFBundleIdentifier</key>\n\t<string>{}</string>",
        agentsweep_core::DAEMON_LABEL
    );
    assert!(plist.contains(&expected), "the plist names {expected}");
}

#[cfg(target_os = "macos")]
#[test]
fn the_daemon_binary_carries_the_info_plist() {
    let binary = fs::read(daemon_binary()).expect("the daemon binary");
    assert!(
        binary
            .windows(EMBEDDED_PLIST.len())
            .any(|window| window == EMBEDDED_PLIST),
        "the daemon binary embeds Info.plist"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn signing_the_daemon_without_an_identifier_yields_the_frozen_one() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let copy = dir.path().join("agentsweepd");
    fs::copy(daemon_binary(), &copy).expect("a copy of the daemon binary");

    // What Tauri runs on each sidecar: an ad hoc identity here, no `-i`.
    let signed = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--options", "runtime"])
        .arg(&copy)
        .output()
        .expect("codesign runs");
    assert!(signed.status.success(), "{:?}", signed);

    let shown = Command::new("/usr/bin/codesign")
        .arg("-dvv")
        .arg(&copy)
        .output()
        .expect("codesign runs");
    let report = String::from_utf8_lossy(&shown.stderr);
    let identifier = report
        .lines()
        .find_map(|line| line.strip_prefix("Identifier="))
        .expect("an Identifier line");
    assert_eq!(identifier, agentsweep_core::DAEMON_LABEL);
}
