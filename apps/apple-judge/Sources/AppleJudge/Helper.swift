import Foundation

/// The helper's protocol: one JSON object in on stdin, one JSON object out on
/// stdout, then exit.
///
/// Requests:
///
/// - `{"command": "check"}` answers `{"available", "reason"?, "context_size"?,
///   "model_version"}`. An unavailable model is an answer, not an error.
/// - `{"command": "count", "text"}` answers `{"token_count"}`.
/// - `{"command": "judge", "instructions", "prompt", "schema"}` answers
///   `{"answer"}`, the JSON the model produced under the schema.
///
/// Every failure answers `{"error", "reason"?}` with a name from `ErrorName`
/// and exits 1; an answer exits 0. Nothing in an answer or an error echoes
/// the request, and nothing is logged.
public enum Helper {
    /// A request larger than this is refused unread. Apple's model sees 4,096
    /// tokens, so a legitimate request is a small fraction of it.
    public static let maximumRequestBytes = 1 << 20

    public struct Reply: Sendable {
        public let body: Data
        public let exitCode: Int32
    }

    public static func respond(to input: Data, using model: some LanguageModelPort) async -> Reply {
        do {
            return answer(try await handle(input, model))
        } catch {
            var body: [String: Any] = ["error": error.name.rawValue]
            if let reason = error.reason { body["reason"] = reason.rawValue }
            return Reply(body: encode(body), exitCode: 1)
        }
    }

    private static func answer(_ body: [String: Any]) -> Reply {
        Reply(body: encode(body), exitCode: 0)
    }

    private static func handle(_ input: Data, _ model: some LanguageModelPort) async throws(HelperError)
        -> [String: Any]
    {
        guard input.count <= maximumRequestBytes else { throw HelperError(.requestTooLarge) }
        guard let request = try? JSONSerialization.jsonObject(with: input) as? [String: Any],
            let command = request["command"] as? String
        else { throw HelperError(.malformedRequest) }

        switch command {
        case "check":
            let state = model.availability()
            var body: [String: Any] = [
                "available": state.reason == nil,
                "model_version": model.modelVersion,
            ]
            if let reason = state.reason { body["reason"] = reason.rawValue }
            if let size = state.contextSize { body["context_size"] = size }
            return body

        case "count":
            guard let text = request["text"] as? String else { throw HelperError(.malformedRequest) }
            try requireAvailable(model)
            return ["token_count": try await model.tokenCount(of: text)]

        case "judge":
            guard let instructions = request["instructions"] as? String,
                let prompt = request["prompt"] as? String,
                let schema = request["schema"] as? [String: Any]
            else { throw HelperError(.malformedRequest) }
            let node = try SchemaNode.parse(schema)
            try requireAvailable(model)
            let text = try await model.judge(instructions: instructions, prompt: prompt, schema: node)
            guard let answer = try? JSONSerialization.jsonObject(with: Data(text.utf8)),
                answer is [String: Any] || answer is [Any]
            else { throw HelperError(.decodingFailure) }
            return ["answer": answer]

        default:
            throw HelperError(.unknownCommand)
        }
    }

    private static func requireAvailable(_ model: some LanguageModelPort) throws(HelperError) {
        if let reason = model.availability().reason {
            throw HelperError(.modelUnavailable, reason: reason)
        }
    }

    private static func encode(_ body: [String: Any]) -> Data {
        // Every value above is a string, a number, a Bool or parsed JSON, so
        // this cannot fail; the fallback keeps the promise of one JSON object.
        (try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes]))
            ?? Data(#"{"error":"generation_failed"}"#.utf8)
    }
}
