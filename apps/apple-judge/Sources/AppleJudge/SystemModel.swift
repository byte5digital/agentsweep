#if arch(arm64)
    import FoundationModels
#endif

/// Apple's on-device model through Foundation Models.
///
/// The framework exists from macOS 26 and only on Apple silicon. It is linked
/// weakly, every use sits behind `#available`, and the Intel slice does not
/// reference it at all: there, and below macOS 26, the model is unavailable
/// with the reason `device_not_eligible`.
///
/// Nothing here reads or writes a file, opens a connection or logs: the
/// framework's own error descriptions are dropped for the error's name.
public struct SystemModel: LanguageModelPort {
    public init() {}

    public var modelVersion: String { ModelVersion.current() }

    public func availability() -> Availability {
        #if arch(arm64)
            if #available(macOS 26.0, *) {
                let model = SystemLanguageModel.default
                switch model.availability {
                case .available:
                    return Availability(reason: nil, contextSize: model.contextSize)
                case .unavailable(let reason):
                    return Availability(reason: Self.reason(of: reason), contextSize: model.contextSize)
                }
            }
        #endif
        return Availability(reason: .deviceNotEligible, contextSize: nil)
    }

    public func tokenCount(of text: String) async throws(HelperError) -> Int {
        #if arch(arm64)
            if #available(macOS 26.4, *) {
                do {
                    return try await SystemLanguageModel.default.tokenCount(for: text)
                } catch {
                    throw Self.helperError(from: error)
                }
            }
            throw HelperError(.tokenCountUnavailable)
        #else
            throw HelperError(.modelUnavailable, reason: .deviceNotEligible)
        #endif
    }

    public func judge(instructions: String, prompt: String, schema: SchemaNode) async throws(HelperError)
        -> String
    {
        #if arch(arm64)
            if #available(macOS 26.0, *) {
                let generationSchema: GenerationSchema
                do {
                    generationSchema = try GenerationSchema(root: schema.dynamic(path: "answer"), dependencies: [])
                } catch {
                    throw HelperError(.invalidSchema)
                }
                // A fresh session per judgement, no tools, no earlier turns.
                let session = LanguageModelSession(model: .default, tools: [], instructions: instructions)
                do {
                    let response = try await session.respond(
                        to: prompt, schema: generationSchema, options: GenerationOptions(temperature: 0))
                    return response.content.jsonString
                } catch {
                    throw Self.helperError(from: error)
                }
            }
        #endif
        throw HelperError(.modelUnavailable, reason: .deviceNotEligible)
    }

    static func helperError(from error: any Error) -> HelperError {
        #if arch(arm64)
            if #available(macOS 26.0, *), let error = error as? LanguageModelSession.GenerationError {
                return HelperError(name(of: error))
            }
        #endif
        return HelperError(.generationFailed)
    }
}

#if arch(arm64)
    @available(macOS 26.0, *)
    extension SystemModel {
        static func name(of error: LanguageModelSession.GenerationError) -> ErrorName {
            switch error {
            case .guardrailViolation: return .guardrailViolation
            case .refusal: return .refusal
            case .rateLimited: return .rateLimited
            case .exceededContextWindowSize: return .contextWindowExceeded
            case .assetsUnavailable: return .assetsUnavailable
            case .concurrentRequests: return .concurrentRequests
            case .unsupportedLanguageOrLocale: return .unsupportedLanguage
            case .decodingFailure: return .decodingFailure
            case .unsupportedGuide: return .unsupportedGuide
            @unknown default: return .unknownGenerationError
            }
        }

        static func reason(of reason: SystemLanguageModel.Availability.UnavailableReason)
            -> UnavailableReason
        {
            switch reason {
            case .deviceNotEligible: return .deviceNotEligible
            case .appleIntelligenceNotEnabled: return .appleIntelligenceNotEnabled
            case .modelNotReady: return .modelNotReady
            @unknown default: return .unknown
            }
        }
    }

    @available(macOS 26.0, *)
    extension SchemaNode {
        /// The schema as Foundation Models takes it. `path` names each object
        /// and choice uniquely, which `GenerationSchema` requires.
        func dynamic(path: String) -> DynamicGenerationSchema {
            switch self {
            case .object(let description, let properties):
                return DynamicGenerationSchema(
                    name: path, description: description,
                    properties: properties.map { property in
                        DynamicGenerationSchema.Property(
                            name: property.name, description: property.schema.description,
                            schema: property.schema.dynamic(path: path + "_" + property.name),
                            isOptional: property.isOptional)
                    })
            case .choice(let description, let values):
                return DynamicGenerationSchema(name: path, description: description, anyOf: values)
            case .array(_, let items, let minimum, let maximum):
                return DynamicGenerationSchema(
                    arrayOf: items.dynamic(path: path + "_item"), minimumElements: minimum,
                    maximumElements: maximum)
            case .string: return DynamicGenerationSchema(type: String.self)
            case .boolean: return DynamicGenerationSchema(type: Bool.self)
            case .integer: return DynamicGenerationSchema(type: Int.self)
            case .number: return DynamicGenerationSchema(type: Double.self)
            }
        }
    }
#endif
