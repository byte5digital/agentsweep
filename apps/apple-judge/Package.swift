// swift-tools-version:6.0
//
// The helper that is AgentSweep's only way to reach Apple's on-device model
// (spec section 4.4). It builds with the Command Line Tools alone: the schema
// is a `DynamicGenerationSchema`, so no Xcode macro plugin is needed.
//
// The app's minimum is macOS 14 while Foundation Models exists from macOS 26,
// so the framework is linked weakly and the helper answers "unavailable" where
// it is missing. `apps/menubar/build-sidecars.sh` builds it for each Apple
// triple and joins the two with lipo, like the other sidecars.

import PackageDescription

let package = Package(
    name: "agentsweep-apple-judge",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "agentsweep-apple-judge", targets: ["agentsweep-apple-judge"])
    ],
    targets: [
        .target(
            name: "AppleJudge",
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-weak_framework", "-Xlinker", "FoundationModels"])
            ]
        ),
        .executableTarget(
            name: "agentsweep-apple-judge",
            dependencies: ["AppleJudge"]
        ),
        .testTarget(
            name: "AppleJudgeTests",
            dependencies: ["AppleJudge"]
        ),
    ]
)
