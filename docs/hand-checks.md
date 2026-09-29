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

- [X] macOS shows a "Background Items Added" notice naming AgentSweep.
- [X] The service is `running` with a pid, and its program is `.../AgentSweep.app/Contents/MacOS/agentsweepd`.
- [X] System Settings, General, Login Items lists AgentSweep under "Open at Login" and under "Allow in the Background".
- [X] `~/agentsweep-hand-check/AgentSweep.app/Contents/MacOS/agentsweep status` prints a Health sentence, not "Protection is off".

Quit from the popover (**Quit AgentSweep (protection stays on)**), or `pkill -x agentsweep-menubar`, then:

- [X] `launchctl print ...` still shows the same pid running, and `agentsweep status` still answers.

## 2. The popover follows Health within a second

Open the app again and click the menu bar icon.

- [-] The popover opens under the icon with the orb, one sentence, "Last check" and Quit. (Opens on the main screen only not on second screen)
- [X] Run `agentsweep scan` from the bundle in a terminal: the sentence turns to "Checking now." and back to the all-clear sentence within a second of the Scan starting and ending.

Seams in the suite: `link::tests::the_view_follows_the_health_on_the_stream` (app) and `a_subscriber_is_told_the_health_first_and_again_when_it_moves` (daemon).

## 3. Killing the daemon shows Protection off, KeepAlive brings it back

```sh
kill -9 $(pgrep -x agentsweepd)
```

- [X] With the popover open, "Protection is off" and the **Open Login Items** button appear at once.
- [X] Within about ten seconds `launchctl print ...` shows a new pid, and the popover returns to the Health sentence without being reopened. (Took longer than 10 Seconds)

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

## 7. The Findings window acts through the daemon and follows the stream

This check needs no hand install. It runs a debug daemon on a temporary home with the chain key in memory, and the bare debug app pointed at it; neither touches the real home, the real socket, the real data directory, the Keychain or Login Items, and the daemon never asks the Rule Feed. Build both with `cargo build -p agentsweep-daemon -p agentsweep-menubar`, then make a home with something to find: a skill whose `SKILL.md` pipes a download from a `.invalid` host into `sh` (Rule 0001), a `.claude.json` holding `{"projects": {}}`, and a `.claude/settings.json` whose `permissions.defaultMode` is `bypassPermissions` (Exposure 0019). Keep the socket path short; macOS allows about a hundred characters.

```sh
w=$(mktemp -d /tmp/asw.XXXX)
# ... lay out $w/home as above, and mkdir $w/data
target/debug/agentsweepd --home $w/home --data-dir $w/data --socket $w/d.sock --key-source memory --log stderr &
AGENTSWEEP_DEV_SOCKET=$w/d.sock AGENTSWEEP_DEV_SHOW_WINDOW=1 target/debug/agentsweep-menubar &
target/debug/agentsweep status --socket $w/d.sock
```

- [ ] The window lists the same open Findings, with the same ids, as `agentsweep status`: kind and name, Severity, Tier, category, Probation state, the plain line and, where there is one, the Drift line.
- [ ] The skill offers Quarantine and Trust this version; the 0019 Exposure offers Keep it as it is and Take this setting out, and never Quarantine.
- [ ] Quarantine asks first, and the question says whether Agent sessions appear to be running (write `$w/home/.claude/sessions/<pid>.json` naming a live pid, for example the shell's, to see the other answer).
- [ ] After Quarantine the card moves to Stopped and decided with its Receipt id without any refresh, and `agentsweep status` says the same; Restore moves it back, Trust this version moves it to trusted.
- [ ] An action the daemon refuses shows one sentence beginning "Nothing was done:" and changes nothing.
- [ ] Scan now shows "Checked N of M Items." while it runs and the last Scan line when it ends, in the window and in the popover.
- [ ] While Scan now runs, every action button in the window is greyed out and a line under the Scan buttons says the actions wait until the check has finished; when the popover leaves "Checking now." the buttons work again without reopening the window.
- [ ] With the Findings of this home open and no Scan running, the popover says "3 things need your decision" with the Threat and Exposure counts, and the menu bar icon shows the exclamation mark.
- [ ] Scan a folder opens the macOS folder picker; a folder with a planted `CLAUDE.md` answers "Do not open yet." with the Finding beneath, a clean one "Safe to open.", both with "Nothing was recorded." and the Rule Pack version in force, and `agentsweep status` is unchanged afterwards.
- [ ] Killing the daemon turns the window to "Protection is off" and hides Scan now and Scan a folder; starting it again brings the list back without reopening the window.
- [ ] With the window open, `lsappinfo info -only ApplicationType -app agentsweep-menubar` says `Foreground` and the app has a Dock icon and a Cmd-Tab entry; after closing the window it says `UIElement` and both are gone. On an installed bundle this is the Tauri issue 15005 check of the release draft.

Stop both with `pkill -x agentsweep-menubar; pkill -x agentsweepd`, then `rm -rf $w` and the three folders a run of the bare binary leaves: `~/Library/Caches/agentsweep-menubar`, `~/Library/WebKit/agentsweep-menubar` and `"$TMPDIR"agentsweep-menubar`.

Seams in the suite: `findings::tests` (the list, the offers per source and state, the stream reducer and the confirmation), `asking::tests` (the answers in the command line interface's words), `folder::tests`, the `window` integration tests of the app (a real daemon on a temporary home: every action followed from the stream, the Folder Scan recording nothing) and, in the daemon, `a_folder_scan_on_request_answers_and_records_nothing` and `a_path_on_a_request_that_takes_none_is_never_answered`.

## Dogfooding: one day with the app

The minimal app's layout and words are placeholders so that the Posture and wording decisions of spec section 8 stay open. The author runs it for a day on their own machine, as an installed bundle, and files one note per question below with what they saw. None of these is decided by the minimal app.

- [ ] Does "N things need your decision", with the Threat and Exposure counts, read well in the popover and in `agentsweep status`? It sits below "Checking now." and above the Rule Pack notices.
- [ ] Which ids, paths, Tiers and Rule ids does the Simple Posture hide, and which stay one click away? The window shows them all today.
- [ ] Is "Restore" enough, or must the button say "Restore and trust this version" before it is pressed? The status does not say whether AgentSweep or the user took an Item out, so the app cannot tell the two apart until the answer comes back.
- [ ] Drift questions offer "Yes, that was me", "No, remove it" and "Trust this version" side by side; spec section 8.5 hides Trust behind technical details in the Simple Posture.
- [ ] Where does an action's answer belong? It shows at the top of the window, with the sessions sentence and the Receipt lines folded under Details.
- [ ] Is the Quarantine confirmation's sessions sentence the one to keep, and should it name the sessions it found?
- [ ] Exposures need "Show me how to fix this" with Open the file; only the 0018 and 0019 fix exists.
- [ ] Scan a folder needs its drop zone and, in the Developer Posture, the equivalent `agentsweep scan <dir>`. The daemon's Folder Scan uses the Rule Pack in force and the command line the bundled one; both name the version they used.
- [ ] The sidebar of spec section 8.1 (Overview, Needs your decision, Worth fixing, Quarantine, Activity, Settings) with counts, and where the list of what was stopped and decided goes.
- [ ] Delete permanently, Reveal in Finder, Untrust and the "rule was withdrawn" line are not offered yet.
- [ ] Closing the window hides it; is that what a person expects of Cmd-W and of the red button, and does Cmd-Q from the regular app's menu quit the menu bar app too?
- [ ] Should Scan now's progress show in the popover, or only the sentence "Checking now."?

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

2026-09-25, ticket 25, macOS 26.6, a developer run only (no hand install): a debug daemon on a temporary home with `--key-source memory` and a socket under `/private/tmp`, and the bare debug app with `AGENTSWEEP_DEV_SOCKET` and `AGENTSWEEP_DEV_SHOW_WINDOW`. The app started without an error, opened its subscription and asked the daemon for the status (two app connections in the daemon's log), and `lsappinfo` said `Foreground` with the window open. The window was not looked at and no button was pressed (no screen access in that session); check 7 is otherwise covered by the suite's seams only. Both processes were stopped, and the temporary home, the socket and the three folders the bare binary left (`~/Library/Caches/agentsweep-menubar`, `~/Library/WebKit/agentsweep-menubar`, `$TMPDIR/agentsweep-menubar`) were removed.

## Release draft additions

Every release draft runs the release checklist, section 9.3 of the specification, in full; the checks above are the part of it that needs a hand install. The lines of that checklist that depend on how this repository builds, so they are easy to miss:

- `codesign -d -r-` on `Contents/MacOS/agentsweepd` shows the identifier `de.byte5.agentsweep.daemon`. Tauri signs sidecars with an identifier derived from the file name, so the release pipeline re-signs the daemon with `-i de.byte5.agentsweep.daemon` after Tauri has signed it, and then signs the bundle again.
- Every Mach-O carries `Timestamp=`, and Dock and Cmd-Tab appear only while the window is open (Tauri issue 15005).
- `TEAM_ID` in the daemon's peer check holds byte5's Team ID. While it is empty a release daemon admits nobody, which is why the checks above use debug sidecars.
- The daemon and CLI sidecars are universal: `lipo -archs` on each shows arm64 and x86_64.
- Every exception in `deny.toml` was read again if Tauri or yara-x moved since the last release, and each one's reason still holds.
- For the first tagged release, `agentsweep-core` and the three adapter crates are publishable and are published to crates.io before the `agentsweep` CLI.
- The Rule Feed's layout is the one the client reads: the index on the `feed` branch holds only the pack version, and each `rules-v<N>` release holds `manifest.json`, one `<KEY ID>.minisig` per signing key and an uncompressed `pack.tar` of the `rules/` and `iocs/` trees.
