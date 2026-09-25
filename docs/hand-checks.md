# Hand checks

Some behaviour of AgentSweep can only be seen on a real Mac with a real, signed bundle: SMAppService registration, launchd's `KeepAlive`, a bundle replaced under a running daemon, and what the menu bar shows. The automated suite covers the decisions behind each of them at a seam (see the tests named below); this list is what a person runs by hand, on their own machine, before a milestone is called done and on every release draft.

A hand install is the real shipped configuration. It registers the real launch agent, and the daemon it starts creates the real data directory, the real socket, the real log and the real Keychain item, and scans the real home. Run it only when you can clean up afterwards, and always finish with the clean-up section.

## Build a test bundle

From the repository root, with the Command Line Tools and Node 22:

```sh
apps/menubar/build-sidecars.sh debug
cd apps/menubar
APPLE_SIGNING_IDENTITY="-" npx --yes @tauri-apps/cli@2.11.5 build --debug --config tauri.bundle.conf.json
```

The bundle lands in `target/debug/bundle/macos/AgentSweep.app`. Debug sidecars are used on purpose: a debug daemon admits any peer of the same user, and a release daemon admits byte5's Team ID only, which is empty until the release milestone fills it in, so a release daemon answers nobody.

Copy the bundle somewhere of its own, so the checks below can replace and remove it without touching the build:

```sh
mkdir -p ~/agentsweep-hand-check
cp -R target/debug/bundle/macos/AgentSweep.app ~/agentsweep-hand-check/
```

## Before: nothing of AgentSweep on the machine

```sh
launchctl print gui/$(id -u)/de.byte5.agentsweep.daemon   # "Could not find service"
ls ~/Library/Application\ Support/de.byte5.agentsweep      # no such file
ls ~/Library/Logs/AgentSweep                               # no such file
ls "$TMPDIR"de.byte5.agentsweep.sock                       # no such file
security find-generic-password -s de.byte5.agentsweep.daemon -a chain-key   # not found
pgrep -fl agentsweep                                       # nothing
```

Anything that is already there belongs to an earlier install; do not run the checks over it.

## 1. The bundle registers the daemon, and the daemon survives quitting the app

```sh
open ~/agentsweep-hand-check/AgentSweep.app
~/agentsweep-hand-check/AgentSweep.app/Contents/MacOS/agentsweep-menubar --developer-status
launchctl print gui/$(id -u)/de.byte5.agentsweep.daemon | grep -E 'state|pid|program'
```

`--developer-status` prints where both registrations stand: `enabled` for the daemon and the login item after the first launch. SMAppService answers `not found` for a service that was never registered, which is why the app registers on that answer too.

- [ ] macOS shows a "Background Items Added" notice naming AgentSweep.
- [ ] The service is `running` with a pid, and its program is `.../AgentSweep.app/Contents/MacOS/agentsweepd`.
- [ ] System Settings, General, Login Items lists AgentSweep under "Open at Login" and under "Allow in the Background".
- [ ] `~/agentsweep-hand-check/AgentSweep.app/Contents/MacOS/agentsweep status` prints a Health sentence, not "Protection is off".

Quit from the popover (**Quit AgentSweep (protection stays on)**), or `pkill -x agentsweep-menubar`, then:

- [ ] `launchctl print ...` still shows the same pid running, and `agentsweep status` still answers.

## 2. The popover follows Health within a second

Open the app again and click the menu bar icon.

- [ ] The popover opens under the icon with the orb, one sentence, "Last check" and Quit.
- [ ] Run `agentsweep scan` from the bundle in a terminal: the sentence turns to "Checking now." and back to the all-clear sentence within a second of the Scan starting and ending.

Seams in the suite: `link::tests::the_view_follows_the_health_on_the_stream` (app) and `a_subscriber_is_told_the_health_first_and_again_when_it_moves` (daemon).

## 3. Killing the daemon shows Protection off, KeepAlive brings it back

```sh
kill -9 $(pgrep -x agentsweepd)
```

- [ ] With the popover open, "Protection is off" and the **Open Login Items** button appear at once.
- [ ] Within about ten seconds `launchctl print ...` shows a new pid, and the popover returns to the Health sentence without being reopened.

Seam in the suite: `link::tests::a_daemon_that_does_not_answer_is_protection_off_with_login_items`.

## 4. Replacing the bundle restarts the daemon from the new one

Build a second bundle with a higher version (raise `version` in the root `Cargo.toml` by a patch, rebuild the sidecars and the bundle, and put the version back afterwards), then swap it in the way an updater does:

```sh
old=$(pgrep -x agentsweepd)
mv ~/agentsweep-hand-check/AgentSweep.app ~/agentsweep-hand-check/AgentSweep-old.app
cp -R target/debug/bundle/macos/AgentSweep.app ~/agentsweep-hand-check/
```

- [ ] Within about ten seconds the old pid is gone and a new one runs; `~/Library/Logs/AgentSweep/daemon.log` says the bundle was replaced and the daemon exited with status 75.
- [ ] `agentsweep --version` from the new bundle and the new daemon's first log line show the new version.
- [ ] Opening the new app does not report "AgentSweep is updating." for more than a moment.

A rebuilt daemon has a new code signature, so on this step macOS may ask whether the new `agentsweepd` may read the Keychain item the old one wrote; allow it. A notarized release keeps its designated requirement across versions and asks nothing.

Seams in the suite: `bundle_watch::tests` (the decision on a temporary bundle) and `link::tests::a_version_mismatch_restarts_the_daemon_once`.

## 5. A bundle that is gone stops the daemon for good

```sh
mv ~/agentsweep-hand-check/AgentSweep.app ~/.Trash/
```

- [ ] About ten seconds later (the grace an update's swap is given) `agentsweepd` is no longer running, the log says the bundle is gone, and it stays down: `launchctl print ...` shows the last exit status 0 and no pid.

Move the bundle back to `~/agentsweep-hand-check/` for the clean-up; the daemon does not start again by itself.

## 6. Idle: no Dock icon, the log rotates

- [ ] With the popover closed, AgentSweep has no Dock icon and no Cmd-Tab entry; `lsappinfo info -only ApplicationType -app agentsweep-menubar` says `UIElement`.
- [ ] `~/Library/Logs/AgentSweep/daemon.log` exists, names paths and ids and never file content, MCP env values, headers or tokens.
- [ ] Rotation at five files of five megabytes is covered by `log::tests::the_log_rotates_at_its_size_and_keeps_its_count_of_files` on a temporary directory; filling 25 MB by hand is not needed.

## Clean up, completely

Unregister both services from the bundle that registered them, then remove everything the run created:

```sh
~/agentsweep-hand-check/AgentSweep.app/Contents/MacOS/agentsweep-menubar --developer-unregister
pkill -x agentsweep-menubar; pkill -x agentsweepd
rm -rf ~/agentsweep-hand-check ~/.Trash/AgentSweep.app
rm -rf ~/Library/Application\ Support/de.byte5.agentsweep ~/Library/Logs/AgentSweep
rm -rf ~/Library/Caches/de.byte5.agentsweep ~/Library/WebKit/de.byte5.agentsweep
rm -rf ~/Library/Caches/agentsweep-menubar ~/Library/WebKit/agentsweep-menubar   # left by a run of the bare binary
rm -f "$TMPDIR"de.byte5.agentsweep.sock
rm -rf "$TMPDIR"de.byte5.agentsweep "$TMPDIR"agentsweep-menubar   # the webview's scratch folders
security delete-generic-password -s de.byte5.agentsweep.daemon -a chain-key
```

Then run the "Before" commands again: every one must report nothing. Login Items must no longer list AgentSweep.

## Record of runs

2026-09-25, ticket 24, macOS 26.6, debug sidecars, ad-hoc signature, bundle in a temporary directory: checks 1, 3 (the launchd side), 4 (with a copy of the same build, so the version did not change), 5 and the Dock half of 6 passed. The log showed "was replaced ... exiting with status 75" once the Scan in hand had finished, and "is gone ... exiting with status 0" with launchd's last exit code 0 and no restart. The popover was not looked at (no screen access in that session), and check 4 was not run with a higher version. Everything the run created was removed as in the clean-up section, including the Keychain item and the WebKit and cache folders.

## Release draft additions

On a signed release draft, also check (spec section 9.3): `codesign -d -r-` on `Contents/MacOS/agentsweepd` shows the identifier `de.byte5.agentsweep.daemon` (Tauri signs sidecars with an identifier derived from the file name, so the release pipeline re-signs the daemon with `-i de.byte5.agentsweep.daemon` and then the bundle), every Mach-O carries `Timestamp=`, and Dock and Cmd-Tab appear only while the window is open (Tauri issue 15005).
