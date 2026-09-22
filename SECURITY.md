# Security policy

AgentSweep is a security utility, so a weakness in it is a weakness in whatever it was meant to protect. This file says where to report one and how the project handles the keys a user's machine has to trust.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting on `byte5digital/agentsweep`: open the Security tab and choose "Report a vulnerability". Please do not open a public issue for anything that puts users at risk before there is a fix.

Say what you found, what an attacker gets out of it, and how to reproduce it. If a proof of concept touches a coding agent's configuration, defang it the way the rule corpus does: hosts under `.invalid` and payloads that decode to `echo`. We will tell you what we found and when a fix ships.

A rule that fires on something harmless is a false positive, not a vulnerability. Those go to the ordinary issue tracker under the false alarm template.

## Supported versions

Only the most recent release receives fixes. There are no update channels and no long lived support branches. Prereleases are installed by hand and are invisible to the updater.

## What the project promises

Self protection is tamper evident, not tamper resistant (ADR 0001). AgentSweep runs with the user's own privileges and no root helper, so it shows that protection is off or that its records were tampered with rather than claiming it can prevent either. The README lists what AgentSweep does not defend against.

Nothing leaves the machine except the three disclosed requests: the Rule Feed fetch, the application update check and the opt-in Claude API call under the user's own key. There is no telemetry and no crash reporting. A report that AgentSweep sent something else is a security report.

## The keys a client trusts

Three keys decide what a machine accepts from the project (ADR 0006):

1. The Apple Developer ID certificate that signs and notarizes the application, the daemon and the CLI.
2. The minisign key of the application updater. Tauri allows exactly one pinned updater key.
3. The minisign keys of the Rule Feed. The binary pins two: the active key, which lives as a secret in the `release` environment, and a standby key generated offline and never uploaded. A Rule Pack is accepted when its manifest carries a valid signature from either pinned key, its version is strictly greater than the one in use, and its minimum engine version is not newer than the client.

## Planned key rotation

Placeholder. This procedure is written out before the first tagged release, as milestone 11 of the build plan requires.

It will cover: how a new Rule Feed key enters the pinned set through an application release, the overlap in which packs carry both signatures for two application releases, how the single updater key is rotated by shipping one release signed with the old key that carries the new one, when the Developer ID certificate is renewed, and who performs each step.

## Key compromise

Placeholder. This procedure is written out before the first tagged release, as milestone 11 of the build plan requires.

It will cover: how a leak is confirmed, moving Rule Feed signing to the offline standby key within the hour, the application release that drops the leaked key, recovering a compromised updater key through the two channels that do not depend on it (the notarized DMG and the Homebrew cask), publishing a GitHub security advisory, and the accepted residual risk that a client which has not updated still accepts a higher numbered pack signed with the leaked key. Such a pack can blind detection or cause quarantines that the user can restore. It can never run code.
