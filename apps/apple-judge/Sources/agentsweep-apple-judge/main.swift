// agentsweep-apple-judge: AgentSweep's only way to reach Apple's on-device
// model. The daemon spawns it once per call, writes one JSON request to its
// stdin, closes it, and reads one JSON answer from its stdout; `Helper` in
// the AppleJudge module holds the protocol. The helper reads no file, writes
// no file, opens no connection and logs nothing.

import AppleJudge
import Foundation

/// Reads stdin to its end, but never more than one byte past the limit, so an
/// oversized request is refused without being held in memory.
func readRequest() -> Data {
    var data = Data()
    let stdin = FileHandle.standardInput
    while data.count <= Helper.maximumRequestBytes {
        guard let chunk = try? stdin.read(upToCount: 64 * 1024), !chunk.isEmpty else { break }
        data.append(chunk)
    }
    return data
}

let reply = await Helper.respond(to: readRequest(), using: SystemModel())
FileHandle.standardOutput.write(reply.body)
FileHandle.standardOutput.write(Data("\n".utf8))
exit(reply.exitCode)
