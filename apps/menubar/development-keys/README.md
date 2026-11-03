# Development updater key, for tests only

The secret half here signs the updater archive of the tests and of the ad hoc CI bundle. It is encrypted with an empty password and protects nothing real.

The app as it ships pins byte5's updater key in `tauri.conf.json`, whose secret half lives only in the `release` environment. The development public half reaches a build only through the configuration override beside the secret, which the updater tests and the ad hoc CI bundle merge in after the bundle configuration. The release never merges it, and the release bundle checker refuses, in release mode, an app that carries it: an update signed with a committed secret must never be one an install accepts.
