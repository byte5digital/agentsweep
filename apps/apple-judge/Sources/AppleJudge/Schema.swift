import Foundation

/// The schema a judgement's answer must follow, read from the JSON Schema the
/// daemon sends: the subset all three Judgement Engines accept and Foundation
/// Models can express as a `DynamicGenerationSchema`. Anything outside it is
/// `invalid_schema`, never a guess.
///
/// JSON objects carry no key order once parsed, so an object's properties are
/// generated in the order of its `required` list, followed by the optional
/// ones in name order. Keywords that constrain nothing here (`$schema`,
/// `title`, `additionalProperties`) are ignored.
public indirect enum SchemaNode: Equatable, Sendable {
    case object(description: String?, properties: [Property])
    case string(description: String?)
    /// A string `enum`: one of the listed values.
    case choice(description: String?, values: [String])
    case array(description: String?, items: SchemaNode, minimumElements: Int?, maximumElements: Int?)
    case boolean(description: String?)
    case integer(description: String?)
    case number(description: String?)

    public struct Property: Equatable, Sendable {
        public let name: String
        public let schema: SchemaNode
        public let isOptional: Bool

        public init(name: String, schema: SchemaNode, isOptional: Bool) {
            self.name = name
            self.schema = schema
            self.isOptional = isOptional
        }
    }

    /// How deep a schema may nest before it is refused.
    public static let maximumDepth = 16

    public static func parse(_ json: Any) throws(HelperError) -> SchemaNode {
        try parse(json, depth: 0)
    }

    var description: String? {
        switch self {
        case .object(let description, _), .string(let description), .choice(let description, _),
            .array(let description, _, _, _), .boolean(let description), .integer(let description),
            .number(let description):
            return description
        }
    }

    private static func parse(_ json: Any, depth: Int) throws(HelperError) -> SchemaNode {
        guard depth <= maximumDepth, let schema = json as? [String: Any] else {
            throw HelperError(.invalidSchema)
        }
        let description: String?
        switch schema["description"] {
        case nil: description = nil
        case let text as String: description = text
        default: throw HelperError(.invalidSchema)
        }
        let type = schema["type"]
        if let values = schema["enum"] {
            guard type == nil || (type as? String) == "string",
                let strings = values as? [String], !strings.isEmpty,
                (values as? [Any])?.allSatisfy({ $0 is String }) == true
            else { throw HelperError(.invalidSchema) }
            return .choice(description: description, values: strings)
        }
        switch type as? String {
        case "string": return .string(description: description)
        case "boolean": return .boolean(description: description)
        case "integer": return .integer(description: description)
        case "number": return .number(description: description)
        case "array":
            guard let items = schema["items"] else { throw HelperError(.invalidSchema) }
            return .array(
                description: description,
                items: try parse(items, depth: depth + 1),
                minimumElements: try count(schema["minItems"]),
                maximumElements: try count(schema["maxItems"]))
        case "object":
            return .object(
                description: description, properties: try properties(of: schema, depth: depth))
        default:
            throw HelperError(.invalidSchema)
        }
    }

    private static func properties(of schema: [String: Any], depth: Int) throws(HelperError)
        -> [Property]
    {
        guard let properties = schema["properties"] as? [String: Any], !properties.isEmpty else {
            throw HelperError(.invalidSchema)
        }
        let required: [String]
        switch schema["required"] {
        case nil: required = []
        case let names as [String]: required = names
        default: throw HelperError(.invalidSchema)
        }
        guard Set(required).count == required.count,
            required.allSatisfy({ properties[$0] != nil })
        else { throw HelperError(.invalidSchema) }
        let optional = properties.keys.filter { !required.contains($0) }.sorted()
        var result: [Property] = []
        for name in required {
            result.append(
                Property(name: name, schema: try parse(properties[name]!, depth: depth + 1), isOptional: false))
        }
        for name in optional {
            result.append(
                Property(name: name, schema: try parse(properties[name]!, depth: depth + 1), isOptional: true))
        }
        return result
    }

    /// A `minItems` or `maxItems`: absent, or a whole number of at least zero.
    private static func count(_ value: Any?) throws(HelperError) -> Int? {
        guard let value else { return nil }
        guard let number = value as? NSNumber,
            CFGetTypeID(number) != CFBooleanGetTypeID(),
            let whole = Int(exactly: number.doubleValue), whole >= 0
        else { throw HelperError(.invalidSchema) }
        return whole
    }
}
