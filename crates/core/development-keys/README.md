# Development Rule Pack keys, for tests only

The two files here are the secret halves of the development Rule Pack key pairs, active and standby, unencrypted on purpose. They protect nothing real.

Only a build with the core's test-only `development-keys` feature pins their public halves, and it then pins no other key: the tests sign their Rule Packs with these secrets and verify them against those public halves. Every shipped binary is built without the feature, pins byte5's release keys instead and does not carry the development public keys at all. The release bundle checker refuses a bundle whose daemon or CLI carries one.

The core published to crates.io leaves this directory out of its package, so the feature builds inside the repository alone. Never sign anything with these keys outside a test.
