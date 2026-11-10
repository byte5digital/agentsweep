# SMAppService once the bundle is in the Trash

Date: 2026-11-10
Question: can the daemon, an SMAppService launch agent, unregister itself or the app's login item after the user dragged the app to the Trash?
Sources: the `SMAppService.h` header of the macOS 26.5 SDK on the build machine, and the Apple pages already cited in `rust-stack.md`. Nothing was run against launchd.

## What Apple says

- An agent service is named by "a plist in the calling app's Contents/Library/LaunchAgents directory". After the drag that plist sits in the Trash, not where the daemon was started from. (`SMAppService.h`, `agentServiceWithPlistName`)
- `mainAppService` is "the main application as a LoginItem". The header does not say which bundle counts as the main application for a helper executable whose bundle has moved. (`SMAppService.h`)
- "Apps that use SMAppService APIs must be code signed." Whether a process whose bundle has moved still passes that check is not documented. (`SMAppService.h`)
- Unregister: "If the service corresponds to a LoginItem, LaunchAgent, or LaunchDaemon and the service is currently running it will be killed. The unregister call will not wait for the service to be reaped." An agent that unregisters itself is killed by its own call. (`SMAppService.h`, `unregisterAndReturnError`)
- `BundleProgram` "allows apps to support a user relocating the app bundle after installation". A drag to the Trash is such a move. (`SMAppService.h`, `agentServiceWithPlistName`)
- After the app is deleted the Login Items entry "may remain visible ... for some time" until the system's maintenance removes it. (Apple, "Updating your app package installer to use the new Service Management API", cited in `rust-stack.md` section 10)

## Answer

No documented way exists for the agent to unregister itself or the app's login item once the bundle is gone, and unregistering itself would kill it mid-call.

## Not verified

- Whether launchd keeps the job loaded until logout (the owner's hand check of 2026-11-10 still found it with `launchctl print` after the daemon exited 0).
- Whether launchd starts the agent again from the Trash at the next login, since `BundleProgram` follows a moved bundle. Hand check section 20 asks for it.
- How long the Login Items entry stays on the current macOS. Hand check section 20 records it.
