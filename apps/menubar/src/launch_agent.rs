//! The launch agent the daemon runs as, and the plist that declares it.
//!
//! The plist lives inside the bundle at `Contents/Library/LaunchAgents`, and
//! SMAppService registers it from there (spec section 9.5): no plist in
//! `~/Library/LaunchAgents`, no `launchctl bootstrap`. `BundleProgram` names
//! the daemon relative to the bundle, so the registration follows the app
//! wherever the user moves it.
//!
//! The committed plist is what the bundle carries; [`render`] is what it must
//! say, and a test holds the two together, so the label, the program and the
//! keep-alive rule are written down once.

use agentsweep_core::{BUNDLE_ID, DAEMON_LABEL};

/// The file name SMAppService is asked for.
pub const PLIST_NAME: &str = "de.byte5.agentsweep.daemon.plist";

/// Where the bundle carries the plist, relative to `Contents`.
pub const PLIST_IN_CONTENTS: &str = "Library/LaunchAgents/de.byte5.agentsweep.daemon.plist";

/// The daemon's binary name, which is also its sidecar name.
pub const DAEMON_BINARY: &str = "agentsweepd";

/// The command line interface's binary name, the second sidecar.
pub const CLI_BINARY: &str = "agentsweep";

/// The daemon relative to the bundle: Tauri puts every sidecar in
/// `Contents/MacOS`, beside the app's own executable.
pub fn bundle_program() -> String {
    format!("Contents/MacOS/{DAEMON_BINARY}")
}

/// The plist, as the bundle carries it.
///
/// `KeepAlive` restarts the daemon whenever it did not exit successfully: a
/// crash, a kill, or the status a daemon whose bundle was replaced exits with.
/// The one successful exit is a daemon whose bundle is gone, and that one is
/// left down for good (spec section 9.5). `ProcessType` `Background` asks
/// launchd for the resource limits of work nobody is waiting for.
pub fn render() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{DAEMON_LABEL}</string>
	<key>BundleProgram</key>
	<string>{program}</string>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>{BUNDLE_ID}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
"#,
        program = bundle_program()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    fn manifest(path: &str) -> String {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
            .unwrap_or_else(|error| panic!("{path}: {error}"))
    }

    fn json(path: &str) -> serde_json::Value {
        serde_json::from_str(&manifest(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
    }

    #[test]
    fn the_committed_plist_is_the_one_the_code_describes() {
        assert_eq!(
            manifest(&format!("LaunchAgents/{PLIST_NAME}")),
            render(),
            "regenerate LaunchAgents/{PLIST_NAME} from launch_agent::render"
        );
    }

    #[test]
    fn the_label_is_the_frozen_daemon_label_and_the_file_is_named_after_it() {
        assert_eq!(DAEMON_LABEL, "de.byte5.agentsweep.daemon");
        assert_eq!(PLIST_NAME, format!("{DAEMON_LABEL}.plist"));
        assert!(PLIST_IN_CONTENTS.ends_with(PLIST_NAME));
        assert!(render().contains(&format!("<string>{DAEMON_LABEL}</string>")));
        assert!(render().contains("<string>Contents/MacOS/agentsweepd</string>"));
    }

    /// The bundle carries the plist where SMAppService looks for it, and the
    /// daemon where `BundleProgram` says it is.
    #[test]
    fn the_bundle_configuration_puts_the_plist_and_the_sidecars_where_they_are_named() {
        let config = json("tauri.conf.json");
        assert_eq!(config["identifier"], BUNDLE_ID);
        assert_eq!(
            config["bundle"]["macOS"]["files"][PLIST_IN_CONTENTS],
            format!("LaunchAgents/{PLIST_NAME}")
        );
        assert_eq!(config["bundle"]["macOS"]["minimumSystemVersion"], "14.0");

        let bundle = json("tauri.bundle.conf.json");
        let sidecars: Vec<&str> = bundle["bundle"]["externalBin"]
            .as_array()
            .expect("the sidecars")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(
            sidecars,
            vec![
                format!("binaries/{DAEMON_BINARY}"),
                format!("binaries/{CLI_BINARY}")
            ]
        );
    }

    /// The app starts as a menu bar agent, so no Dock icon shows before the
    /// activation policy is set (spec section 8.1).
    #[test]
    fn the_app_starts_without_a_dock_icon() {
        let info = manifest("Info.plist");
        assert!(info.contains("<key>LSUIElement</key>\n\t<true/>"), "{info}");
    }

    /// The app's own executable must not be called `agentsweep`: the command
    /// line interface is, and both sit in `Contents/MacOS` on a file system
    /// that does not tell `AgentSweep` from `agentsweep`.
    #[test]
    fn the_app_executable_does_not_collide_with_a_sidecar() {
        let config = json("tauri.conf.json");
        let main = config["mainBinaryName"]
            .as_str()
            .expect("a main binary name");
        for sidecar in [DAEMON_BINARY, CLI_BINARY] {
            assert!(!main.eq_ignore_ascii_case(sidecar), "{main}");
        }
    }
}
