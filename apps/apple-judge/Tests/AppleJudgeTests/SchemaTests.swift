import Foundation
import Testing

@testable import AppleJudge

private func parse(_ text: String) throws(HelperError) -> SchemaNode {
    let json = try! JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed])
    return try SchemaNode.parse(json)
}

@Suite struct Schema {
    @Test func theVerdictSchemaIsReadInTheOrderOfItsRequiredList() throws {
        let node = try parse(
            """
            {"type":"object","additionalProperties":false,"description":"a Verdict",
             "required":["verdict","category","reason","evidence"],
             "properties":{
               "evidence":{"type":"array","items":{"type":"string"},"maxItems":5},
               "reason":{"type":"string","description":"why"},
               "category":{"type":"string","enum":["none","data_exfiltration"]},
               "verdict":{"enum":["malicious","benign","unsure"]}}}
            """)
        #expect(
            node
                == .object(
                    description: "a Verdict",
                    properties: [
                        .init(
                            name: "verdict", schema: .choice(description: nil, values: ["malicious", "benign", "unsure"]),
                            isOptional: false),
                        .init(
                            name: "category",
                            schema: .choice(description: nil, values: ["none", "data_exfiltration"]),
                            isOptional: false),
                        .init(name: "reason", schema: .string(description: "why"), isOptional: false),
                        .init(
                            name: "evidence",
                            schema: .array(
                                description: nil, items: .string(description: nil), minimumElements: nil,
                                maximumElements: 5),
                            isOptional: false),
                    ]))
    }

    @Test func propertiesOutsideTheRequiredListAreOptionalAndFollowInNameOrder() throws {
        let node = try parse(
            """
            {"type":"object","required":["b"],
             "properties":{"d":{"type":"boolean"},"b":{"type":"integer"},"c":{"type":"number"}}}
            """)
        #expect(
            node
                == .object(
                    description: nil,
                    properties: [
                        .init(name: "b", schema: .integer(description: nil), isOptional: false),
                        .init(name: "c", schema: .number(description: nil), isOptional: true),
                        .init(name: "d", schema: .boolean(description: nil), isOptional: true),
                    ]))
    }

    @Test(arguments: [
        #"{"type":"null"}"#,
        #"{"type":["string","null"]}"#,
        #"{}"#,
        #""string""#,
        #"{"anyOf":[{"type":"string"}]}"#,
        ##"{"$ref":"#/defs/x"}"##,
        #"{"type":"string","enum":[]}"#,
        #"{"type":"string","enum":[1,2]}"#,
        #"{"type":"integer","enum":["a"]}"#,
        #"{"type":"array"}"#,
        #"{"type":"array","items":{"type":"string"},"maxItems":true}"#,
        #"{"type":"array","items":{"type":"string"},"minItems":-1}"#,
        #"{"type":"object"}"#,
        #"{"type":"object","properties":{}}"#,
        #"{"type":"object","properties":{"a":{"type":"string"}},"required":["b"]}"#,
        #"{"type":"object","properties":{"a":{"type":"date"}}}"#,
        #"{"type":"string","description":7}"#,
    ])
    func whatTheHelperCannotExpressIsAnInvalidSchema(text: String) {
        #expect(throws: HelperError(.invalidSchema)) { try parse(text) }
    }

    @Test func aDeeplyNestedSchemaIsRefusedRatherThanRecursedWithoutEnd() {
        var text = #"{"type":"string"}"#
        for _ in 0..<(SchemaNode.maximumDepth + 1) {
            text = #"{"type":"array","items":"# + text + "}"
        }
        #expect(throws: HelperError(.invalidSchema)) { try parse(text) }
    }
}

@Suite struct Names {
    @Test func everyErrorHasItsOwnName() {
        let names = ErrorName.allCases.map(\.rawValue)
        #expect(Set(names).count == names.count)
        for name in names {
            #expect(name.allSatisfy { $0.isLowercase || $0 == "_" }, "\(name)")
        }
    }

    @Test func theModelVersionIsTheFullMacOSBuildString() {
        #expect(
            ModelVersion.format(
                OperatingSystemVersion(majorVersion: 26, minorVersion: 6, patchVersion: 2), build: "25G83")
                == "26.6.2 (25G83)")
        #expect(
            ModelVersion.format(
                OperatingSystemVersion(majorVersion: 26, minorVersion: 4, patchVersion: 0), build: "25E5")
                == "26.4.0 (25E5)")
    }

    @Test func theRunningSystemHasABuildNumber() {
        let version = ModelVersion.current()
        #expect(version.hasSuffix(")"), "\(version)")
        #expect(!version.contains("()"), "\(version)")
    }
}
