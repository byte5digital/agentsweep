#if arch(arm64)
    import FoundationModels
    import Testing

    @testable import AppleJudge

    /// Every case of the framework's `GenerationError` maps to its own error
    /// name. The values can only be made where the framework runs (macOS 26 on
    /// Apple silicon); elsewhere the test has nothing to construct and passes
    /// without checking, which its name in the log does not hide.
    @Suite struct GenerationErrorMapping {
        @Test func everyGenerationErrorCaseHasADistinctName() {
            guard #available(macOS 26.0, *) else { return }
            typealias GenerationError = LanguageModelSession.GenerationError
            let context = GenerationError.Context(debugDescription: "defanged")
            let cases: [(GenerationError, ErrorName)] = [
                (.exceededContextWindowSize(context), .contextWindowExceeded),
                (.assetsUnavailable(context), .assetsUnavailable),
                (.guardrailViolation(context), .guardrailViolation),
                (.unsupportedGuide(context), .unsupportedGuide),
                (.unsupportedLanguageOrLocale(context), .unsupportedLanguage),
                (.decodingFailure(context), .decodingFailure),
                (.rateLimited(context), .rateLimited),
                (.concurrentRequests(context), .concurrentRequests),
                (
                    .refusal(GenerationError.Refusal(transcriptEntries: []), context),
                    .refusal
                ),
            ]
            for (error, name) in cases {
                #expect(SystemModel.name(of: error) == name)
            }
            let names = cases.map { SystemModel.name(of: $0.0) }
            #expect(Set(names).count == cases.count)
        }

        @Test func anErrorThatIsNotAGenerationErrorIsAGenerationFailure() {
            struct Other: Error {}
            #expect(SystemModel.helperError(from: Other()) == HelperError(.generationFailed))
        }

        /// The schema a judgement sends becomes a `GenerationSchema`; making
        /// one needs the framework but not the model.
        @Test func theVerdictSchemaBecomesAGenerationSchema() throws {
            guard #available(macOS 26.0, *) else { return }
            let node = SchemaNode.object(
                description: nil,
                properties: [
                    .init(
                        name: "verdict", schema: .choice(description: nil, values: ["malicious", "benign", "unsure"]),
                        isOptional: false),
                    .init(name: "category", schema: .choice(description: nil, values: ["none"]), isOptional: false),
                    .init(name: "reason", schema: .string(description: "why"), isOptional: false),
                    .init(
                        name: "evidence",
                        schema: .array(
                            description: nil, items: .string(description: nil), minimumElements: nil,
                            maximumElements: nil),
                        isOptional: false),
                    .init(name: "score", schema: .integer(description: nil), isOptional: true),
                ])
            _ = try GenerationSchema(root: node.dynamic(path: "answer"), dependencies: [])
        }

        @Test func everyUnavailableReasonMapsToItsName() {
            guard #available(macOS 26.0, *) else { return }
            #expect(SystemModel.reason(of: .deviceNotEligible) == .deviceNotEligible)
            #expect(SystemModel.reason(of: .appleIntelligenceNotEnabled) == .appleIntelligenceNotEnabled)
            #expect(SystemModel.reason(of: .modelNotReady) == .modelNotReady)
        }
    }
#endif
