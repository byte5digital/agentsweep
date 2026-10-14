/// Every error the helper answers with, by the name it carries on the wire.
///
/// The names are the contract with the daemon's Apple engine: each one is no
/// Verdict there, and `rate_limited` is the one it retries (spec section 4.4).
public enum ErrorName: String, CaseIterable, Sendable {
    // The request itself.
    case malformedRequest = "malformed_request"
    case requestTooLarge = "request_too_large"
    case unknownCommand = "unknown_command"
    case invalidSchema = "invalid_schema"

    // The model, before anything is asked of it.
    case modelUnavailable = "model_unavailable"
    case tokenCountUnavailable = "token_count_unavailable"

    // The framework's `LanguageModelSession.GenerationError`, one name per case.
    case guardrailViolation = "guardrail_violation"
    case refusal = "refusal"
    case rateLimited = "rate_limited"
    case contextWindowExceeded = "context_window_exceeded"
    case assetsUnavailable = "assets_unavailable"
    case concurrentRequests = "concurrent_requests"
    case unsupportedLanguage = "unsupported_language"
    case decodingFailure = "decoding_failure"
    case unsupportedGuide = "unsupported_guide"
    /// A case a later framework adds that this helper does not know yet.
    case unknownGenerationError = "unknown_generation_error"

    /// Anything else the framework threw.
    case generationFailed = "generation_failed"
}

/// Why Apple's model cannot be used, as the framework names it.
public enum UnavailableReason: String, Sendable {
    case deviceNotEligible = "device_not_eligible"
    case appleIntelligenceNotEnabled = "apple_intelligence_not_enabled"
    case modelNotReady = "model_not_ready"
    /// A reason a later framework adds that this helper does not know yet.
    case unknown = "unknown"
}

/// A typed error. It never carries content from the request or the model:
/// the helper logs no content, and neither do its answers.
public struct HelperError: Error, Equatable, Sendable {
    public let name: ErrorName
    /// Set on `model_unavailable` only.
    public let reason: UnavailableReason?

    public init(_ name: ErrorName, reason: UnavailableReason? = nil) {
        self.name = name
        self.reason = reason
    }
}
