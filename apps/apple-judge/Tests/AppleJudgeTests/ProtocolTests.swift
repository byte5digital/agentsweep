import Foundation
import Testing

@testable import AppleJudge

/// A model that never reaches Apple's: the protocol is tested against it, so
/// the suite passes on a Mac without Apple Intelligence and in CI.
struct FakeModel: LanguageModelPort {
    var state = Availability(reason: nil, contextSize: 4096)
    var modelVersion = "26.6.2 (25G83)"
    var tokens: Result<Int, HelperError> = .success(42)
    var answer: Result<String, HelperError> = .success(
        #"{"verdict":"benign","category":"none","reason":"fixed","evidence":[]}"#)

    func availability() -> Availability { state }

    func tokenCount(of text: String) async throws(HelperError) -> Int {
        try tokens.get()
    }

    func judge(instructions: String, prompt: String, schema: SchemaNode) async throws(HelperError)
        -> String
    {
        try answer.get()
    }
}

private func reply(_ text: String, _ model: FakeModel = FakeModel()) async -> (
    [String: Any], Int32
) {
    let reply = await Helper.respond(to: Data(text.utf8), using: model)
    let object = try? JSONSerialization.jsonObject(with: reply.body) as? [String: Any]
    #expect(object != nil, "the reply is always one JSON object")
    return (object ?? [:], reply.exitCode)
}

private let verdictSchema = """
    {"type":"object","additionalProperties":false,
     "required":["verdict","category","reason","evidence"],
     "properties":{
       "verdict":{"type":"string","enum":["malicious","benign","unsure"]},
       "category":{"type":"string","enum":["none","data_exfiltration"]},
       "reason":{"type":"string"},
       "evidence":{"type":"array","items":{"type":"string"}}}}
    """

@Suite struct Check {
    @Test func anAvailableModelReportsItsContextSizeAndModelVersion() async {
        let (body, code) = await reply(#"{"command":"check"}"#)
        #expect(code == 0)
        #expect(body["available"] as? Bool == true)
        #expect(body["context_size"] as? Int == 4096)
        #expect(body["model_version"] as? String == "26.6.2 (25G83)")
        #expect(body["reason"] == nil)
    }

    @Test(arguments: [
        (UnavailableReason.deviceNotEligible, "device_not_eligible"),
        (.appleIntelligenceNotEnabled, "apple_intelligence_not_enabled"),
        (.modelNotReady, "model_not_ready"),
    ])
    func anUnavailableModelNamesTheReasonAndExitsCleanly(reason: UnavailableReason, name: String)
        async
    {
        var model = FakeModel()
        model.state = Availability(reason: reason, contextSize: nil)
        let (body, code) = await reply(#"{"command":"check"}"#, model)
        #expect(code == 0)
        #expect(body["available"] as? Bool == false)
        #expect(body["reason"] as? String == name)
        #expect(body["context_size"] == nil)
        #expect(body["model_version"] as? String == "26.6.2 (25G83)")
    }
}

@Suite struct Count {
    @Test func aTextIsCounted() async {
        let (body, code) = await reply(#"{"command":"count","text":"echo hello"}"#)
        #expect(code == 0)
        #expect(body["token_count"] as? Int == 42)
    }

    @Test func anUnavailableModelCountsNothing() async {
        var model = FakeModel()
        model.state = Availability(reason: .modelNotReady, contextSize: nil)
        let (body, code) = await reply(#"{"command":"count","text":"echo"}"#, model)
        #expect(code == 1)
        #expect(body["error"] as? String == "model_unavailable")
        #expect(body["reason"] as? String == "model_not_ready")
    }

    @Test func aCountTheModelCannotMakeIsATypedError() async {
        var model = FakeModel()
        model.tokens = .failure(HelperError(.tokenCountUnavailable))
        let (body, code) = await reply(#"{"command":"count","text":"echo"}"#, model)
        #expect(code == 1)
        #expect(body["error"] as? String == "token_count_unavailable")
    }
}

@Suite struct Judge {
    @Test func theAnswerComesBackAsJSON() async {
        let request = #"{"command":"judge","instructions":"i","prompt":"p","schema":"#
            + verdictSchema + "}"
        let (body, code) = await reply(request)
        #expect(code == 0)
        let answer = body["answer"] as? [String: Any]
        #expect(answer?["verdict"] as? String == "benign")
        #expect((answer?["evidence"] as? [Any])?.isEmpty == true)
    }

    @Test(arguments: [
        ErrorName.guardrailViolation, .refusal, .rateLimited, .contextWindowExceeded,
        .assetsUnavailable, .concurrentRequests, .unsupportedLanguage, .decodingFailure,
        .unsupportedGuide, .unknownGenerationError, .generationFailed,
    ])
    func aGenerationErrorIsNamed(name: ErrorName) async {
        var model = FakeModel()
        model.answer = .failure(HelperError(name))
        let request = #"{"command":"judge","instructions":"i","prompt":"p","schema":"#
            + verdictSchema + "}"
        let (body, code) = await reply(request, model)
        #expect(code == 1)
        #expect(body["error"] as? String == name.rawValue)
        #expect(body["answer"] == nil)
    }

    @Test func anUnavailableModelJudgesNothing() async {
        var model = FakeModel()
        model.state = Availability(reason: .appleIntelligenceNotEnabled, contextSize: nil)
        let request = #"{"command":"judge","instructions":"i","prompt":"p","schema":"#
            + verdictSchema + "}"
        let (body, _) = await reply(request, model)
        #expect(body["error"] as? String == "model_unavailable")
        #expect(body["reason"] as? String == "apple_intelligence_not_enabled")
    }

    @Test func anAnswerThatIsNotJSONIsADecodingFailure() async {
        var model = FakeModel()
        model.answer = .success("not json")
        let request = #"{"command":"judge","instructions":"i","prompt":"p","schema":"#
            + verdictSchema + "}"
        let (body, code) = await reply(request, model)
        #expect(code == 1)
        #expect(body["error"] as? String == "decoding_failure")
    }

    @Test func anUnsupportedSchemaNeverReachesTheModel() async {
        var model = FakeModel()
        model.answer = .failure(HelperError(.generationFailed))
        let request = #"{"command":"judge","instructions":"i","prompt":"p","schema":{"type":"null"}}"#
        let (body, code) = await reply(request, model)
        #expect(code == 1)
        #expect(body["error"] as? String == "invalid_schema")
    }
}

@Suite struct MalformedInput {
    @Test(arguments: [
        "",
        "not json",
        "[1,2]",
        "\"check\"",
        "{",
        #"{"command":7}"#,
        #"{"text":"echo"}"#,
        #"{"command":"count"}"#,
        #"{"command":"count","text":3}"#,
        #"{"command":"judge","prompt":"p","schema":{"type":"string"}}"#,
        #"{"command":"judge","instructions":"i","schema":{"type":"string"}}"#,
        #"{"command":"judge","instructions":"i","prompt":"p"}"#,
        #"{"command":"judge","instructions":"i","prompt":"p","schema":"string"}"#,
    ])
    func malformedInputIsATypedError(input: String) async {
        let (body, code) = await reply(input)
        #expect(code == 1)
        #expect(body["error"] as? String == "malformed_request")
    }

    @Test func anUnknownCommandIsNamed() async {
        let (body, code) = await reply(#"{"command":"pull"}"#)
        #expect(code == 1)
        #expect(body["error"] as? String == "unknown_command")
    }

    @Test func invalidUTF8IsATypedError() async {
        let reply = await Helper.respond(to: Data([0x7B, 0xFF, 0xFE, 0x7D]), using: FakeModel())
        let body = try? JSONSerialization.jsonObject(with: reply.body) as? [String: Any]
        #expect(reply.exitCode == 1)
        #expect(body?["error"] as? String == "malformed_request")
    }

    @Test func anOversizedRequestIsRefusedUnread() async {
        let huge = Data(repeating: 0x20, count: Helper.maximumRequestBytes + 1)
        let reply = await Helper.respond(to: huge, using: FakeModel())
        let body = try? JSONSerialization.jsonObject(with: reply.body) as? [String: Any]
        #expect(reply.exitCode == 1)
        #expect(body?["error"] as? String == "request_too_large")
    }

    /// The helper logs no content, and its errors do not carry it either.
    @Test func anErrorNeverEchoesTheRequest() async {
        let secret = "sk-defanged-0000"
        for input in [
            "{\"command\":\"" + secret + "\"}",
            "{\"command\":\"count\",\"text\":[\"" + secret + "\"]}",
            "{\"command\":\"judge\",\"instructions\":\"i\",\"prompt\":\"p\",\"schema\":{\"type\":\""
                + secret + "\"}}",
            secret,
        ] {
            let reply = await Helper.respond(to: Data(input.utf8), using: FakeModel())
            let text = String(decoding: reply.body, as: UTF8.self)
            #expect(!text.contains(secret), "\(text)")
        }
    }
}
