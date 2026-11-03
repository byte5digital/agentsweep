# Security policy

AgentSweep is a security utility, so a weakness in it is a weakness in whatever it was meant to protect. This file says where to report one and how the project handles the keys a user's machine has to trust.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting on `byte5digital/agentsweep`: open the Security tab and choose "Report a vulnerability". Please do not open a public issue for anything that puts users at risk before there is a fix.

Say what you found, what an attacker gets out of it, and how to reproduce it. If a proof of concept touches a coding agent's configuration, defang it the way the rule corpus does: hosts under `.invalid` and payloads that decode to `echo`. We will tell you what we found and when a fix ships.

A rule that fires on something harmless is a false positive, not a vulnerability. Those go to the ordinary issue tracker under the false alarm template, which the app's Report false positive button fills in for you.

## Supported versions

Only the most recent release receives fixes. There are no update channels and no long lived support branches. Prereleases are installed by hand and are invisible to the updater.

## What the project promises

Self protection is tamper evident, not tamper resistant (ADR 0001). AgentSweep runs with the user's own privileges and no root helper, so it shows that protection is off or that its records were tampered with rather than claiming it can prevent either. The README lists what AgentSweep does not defend against.

Nothing leaves the machine except the three disclosed requests: the Rule Feed fetch, the application update check and the opt-in Claude API call under the user's own key. There is no telemetry and no crash reporting. A report that AgentSweep sent something else is a security report.

## The keys a client trusts

Three keys decide what a machine accepts from the project (ADR 0006):

1. The Apple Developer ID certificate that signs and notarizes the application, the daemon and the CLI.
2. The minisign key of the application updater. Tauri allows exactly one pinned updater key.
3. The minisign keys that sign Rule Packs for the Rule Feed. The binary pins two: the active key, which lives as a secret in the `release` environment, and a standby key generated offline and never uploaded. A Rule Pack is accepted when its manifest carries a valid signature from any pinned key, its version is strictly greater than the one in use, and its minimum engine version is not newer than the client.

## Who does what

Three roles appear in the procedures below, and every step names the one that performs it:

- The owner administers the repository and its `release` environment: the owner adds and removes the environment's secrets, runs the release checklist on every draft release and publishes it.
- The Account Holder of byte5's membership in the Apple Developer Program creates the Developer ID certificate.
- A reviewer of the `release` environment approves each run that reaches the signing secrets. No release of the app and no Rule Pack is signed without that approval.

## Planned key rotation

A planned rotation gives clients in the field the time to trust a new key before the old one stops signing. No step writes a secret key anywhere but the `release` environment and byte5's password manager.

### A Rule Pack key

1. The owner generates the new Rule Pack key pair offline and keeps its secret half in byte5's password manager.
2. An app release adds the new public key to the pinned set, beside the old active key and the standby key. A reviewer of the `release` environment approves the run, and the owner runs the release checklist on the draft and publishes it.
3. Once that release is published, the owner adds the new secret key to the `release` environment as the next Rule Pack key, beside the old one. The Rule Pack release workflow signs each manifest with every Rule Pack key present in the `release` environment, so from now on each Rule Pack carries both signatures, the old key's and the new key's. A client accepts a Rule Pack when any one signature comes from a key it pins, so a client that pins only the old key and a client that pins both accept the same Rule Packs from the Rule Feed. Before it publishes, the workflow verifies every Rule Pack against the keys pinned in the commit it was built from, and a reviewer of the `release` environment approves every run, as always.
4. The overlap lasts two app releases: the one that added the new key and the one after it. Every Rule Pack published in that time carries both signatures.
5. The app release after the overlap drops the old key from the pinned set; the new key is the active key from then on. Once that release is published, the owner puts the new secret key in the old one's place in the `release` environment and removes the old one, so Rule Packs carry the new key's signature alone. A client still older than the release that added the new key then receives no newer Rule Pack until it updates the app; the Rule Pack it has keeps working.

The standby key stays pinned and untouched throughout.

### The updater key

The application updater pins exactly one key, so it is rotated by one release that both sides of the change trust.

1. The owner generates the new updater key pair.
2. One app release carries the new updater public key in its configuration and is signed with the old updater key, so every client in the field verifies it with the key it already pins and installs it. A reviewer of the `release` environment approves the run, and the owner runs the release checklist on the draft and publishes it.
3. Once that release is published, the owner replaces the old updater secret key in the `release` environment with the new one. Every later release is signed with the new key, which every client that installed the rotating release trusts.

A client that never installed the rotating release cannot verify the releases after it. It is updated through the two channels that do not depend on the updater key, the notarized DMG and the Homebrew cask, as after a compromise.

### The Developer ID certificate

The Developer ID certificate is renewed before its expiry date. The owner reads that date on every draft release, as an item of the release checklist, so an approaching expiry is seen at a release and never discovered by a failed one. The Account Holder creates the renewed Developer ID Application certificate, and the owner replaces the certificate and its password in the `release` environment.

## Key compromise

A key counts as leaked as soon as anyone other than the project's release workflows could have used it.

### Confirming a leak

A leak shows up as a report through private vulnerability reporting, as a secret seen outside the `release` environment (in a log, an artifact or anywhere else), or as a Rule Pack, a signature or an update the project did not publish. The owner confirms it against the project's own record. Every genuine Rule Pack, DMG and updater archive carries a GitHub artifact attestation made by the project's release workflows, and the `release` environment's deployment history lists every run that reached the signing secrets and the reviewer who approved it. A validly signed file without a matching attestation, or a run nobody on the project started, confirms the leak. When the evidence stays unclear, the owner treats the key as leaked: moving to the standby key costs one app release and loses nothing.

### The active Rule Pack key

1. The owner moves Rule Pack signing to the standby key within the hour of the confirmation: the owner takes the standby secret key from byte5's password manager, puts it into the `release` environment as the active Rule Pack key and removes the leaked key. Every client in the field already pins the standby key, so from that hour the next Rule Pack, approved by a reviewer of the `release` environment like every other, is signed by the standby key and accepted everywhere without an app update.
2. An app release drops the leaked key from the pinned set. The former standby key is the active key from then on, and the same release pins a new standby key, which the owner generates offline and keeps in byte5's password manager, so the pinned set holds two keys again. A reviewer of the `release` environment approves the run, and the owner runs the release checklist on the draft and publishes it.
3. The owner publishes a GitHub security advisory that tells users to update the app to that release.

### The updater key

1. The owner removes the leaked updater key from the `release` environment at once and puts a newly generated updater secret key in its place.
2. An app release pins the new updater public key and is signed with the new key. Clients in the field still pin the leaked key and cannot take this release through the updater, so it reaches them through the two channels that do not depend on the updater key: the notarized DMG attached to the GitHub release, which macOS checks against the Developer ID signature, and the Homebrew cask in byte5's tap, which moves to the new release when the owner publishes it. A reviewer of the `release` environment approves the run, and the owner runs the release checklist on the draft and publishes it.
3. The owner publishes a GitHub security advisory that tells users to install that release from the DMG or by upgrading the Homebrew cask, without waiting for the in-app update.

### The advisory

The owner publishes a GitHub security advisory for every confirmed leak. It says which key leaked, since when it may have been used, which release drops it and what a user has to do. Private vulnerability reporting stays the way to tell the project about anything that follows.

### The risk that remains

A client that has not updated the app still pins the leaked Rule Pack key, so it still accepts a Rule Pack signed with that key whose version is higher than the one in use. The project accepts this risk. Such a Rule Pack can blind detection or cause Quarantines, which the user can restore. It can never run code: a Rule Pack holds only Rules and Indicator Lists, which the scanner reads as data. The advisory tells users to update.

A leaked updater key weighs more, because an update ships code. A client trusts that key until it has installed the release from the DMG or the Homebrew cask, which is why the advisory asks every user to do so at once.
