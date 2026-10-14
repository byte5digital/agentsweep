import Foundation

/// Whether the model can be used and, where the framework says, how large its
/// context is.
public struct Availability: Equatable, Sendable {
    /// `nil` when the model is available.
    public var reason: UnavailableReason?
    /// The framework's `contextSize`, where the framework exists.
    public var contextSize: Int?

    public init(reason: UnavailableReason?, contextSize: Int?) {
        self.reason = reason
        self.contextSize = contextSize
    }
}

/// What the helper needs from a language model. `SystemModel` is Apple's
/// on-device model; the tests use a fake, so they never depend on Apple
/// Intelligence being on.
public protocol LanguageModelPort: Sendable {
    /// The identifier the daemon puts in the Verdict cache key.
    var modelVersion: String { get }
    func availability() -> Availability
    func tokenCount(of text: String) async throws(HelperError) -> Int
    /// One judgement in a fresh session at temperature 0 with no tools; the
    /// answer is the JSON text the constrained generation produced.
    func judge(instructions: String, prompt: String, schema: SchemaNode) async throws(HelperError)
        -> String
}

/// The model version of Apple's on-device model, which ships with the
/// operating system: the full macOS version and build number, so any OS
/// update, even one that keeps the version, invalidates Apple Verdicts.
public enum ModelVersion {
    public static func current() -> String {
        format(ProcessInfo.processInfo.operatingSystemVersion, build: build())
    }

    static func format(_ version: OperatingSystemVersion, build: String) -> String {
        "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion) (\(build))"
    }

    /// The build number from the kernel (`kern.osversion`), read without
    /// touching the disk.
    private static func build() -> String {
        var size = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else {
            return "unknown"
        }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &bytes, &size, nil, 0) == 0 else { return "unknown" }
        return String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
