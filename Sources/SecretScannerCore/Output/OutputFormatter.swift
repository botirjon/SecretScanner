import Foundation
import Rainbow

// MARK: - OutputFormatter Protocol

public protocol OutputFormatter: Sendable {
    func format(_ result: ScanResult, verbose: Bool) -> String
}

// MARK: - Console Formatter

public struct ConsoleFormatter: OutputFormatter {

    public init() {}

    public func format(_ result: ScanResult, verbose: Bool) -> String {
        var output = ""

        if result.findings.isEmpty {
            output += "✅ No secrets found!\n\n"
        } else {
            output += "🚨 Found \(result.findings.count) potential secret(s)!\n\n"

            for finding in result.findings {
                output += formatFinding(finding)
                output += "\n"
            }
        }

        // Summary
        output += String(repeating: "─", count: 60) + "\n"
        output += "📊 Summary\n"
        output += "   Files scanned: \(result.scannedFiles)\n"
        output += "   Lines scanned: \(result.scannedLines)\n"
        output += "   Secrets found: \(result.findings.count)\n"
        output += "   Duration: \(String(format: "%.2f", result.duration))s\n"

        if !result.errors.isEmpty && verbose {
            output += "\n⚠️ Errors (\(result.errors.count)):\n"
            for error in result.errors {
                output += "   \(error.file): \(error.message)\n"
            }
        }

        return output
    }

    private func formatFinding(_ finding: Finding) -> String {
        var output = ""

        let severityColor = severityToColor(finding.severity)
        let severityEmoji = finding.severity.emoji

        output += "\(severityEmoji) \(finding.severity.rawValue.uppercased())".applyingColor(severityColor) + "\n"
        output += "   Rule: \(finding.ruleId)\n"
        output += "   Description: \(finding.description)\n"
        output += "   File: \(finding.filePath):\(finding.lineNumber):\(finding.columnStart)\n"
        output += "   Secret: \(finding.secret)\n"
        output += "   Fingerprint: \(finding.fingerprint)\n"

        return output
    }

    private func severityToColor(_ severity: Severity) -> NamedColor {
        switch severity {
        case .critical: return .red
        case .high: return .yellow
        case .medium: return .cyan
        case .low: return .green
        case .info: return .white
        }
    }
}

// MARK: - JSON Formatter

public struct JSONFormatter: OutputFormatter {

    public init() {}

    public func format(_ result: ScanResult, verbose: Bool) -> String {
        let output = JSONOutput(
            findings: result.findings,
            summary: JSONSummary(
                filesScanned: result.scannedFiles,
                linesScanned: result.scannedLines,
                secretsFound: result.findings.count,
                duration: result.duration
            ),
            errors: verbose ? result.errors.map { JSONError(file: $0.file, message: $0.message) } : nil
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        guard let data = try? encoder.encode(output),
              let jsonString = String(data: data, encoding: .utf8) else {
            return "{\"error\": \"Failed to encode results\"}"
        }

        return jsonString
    }
}

private struct JSONOutput: Codable {
    let findings: [Finding]
    let summary: JSONSummary
    let errors: [JSONError]?
}

private struct JSONSummary: Codable {
    let filesScanned: Int
    let linesScanned: Int
    let secretsFound: Int
    let duration: TimeInterval
}

private struct JSONError: Codable {
    let file: String
    let message: String
}

// MARK: - SARIF Formatter

public struct SARIFFormatter: OutputFormatter {

    public init() {}

    public func format(_ result: ScanResult, verbose: Bool) -> String {
        let sarif = SARIFOutput(
            version: "2.1.0",
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            runs: [
                SARIFRun(
                    tool: SARIFTool(
                        driver: SARIFDriver(
                            name: "SecretScanner",
                            version: "1.0.0",
                            informationUri: "https://github.com/yourusername/SecretScanner",
                            rules: buildRules(from: result.findings)
                        )
                    ),
                    results: result.findings.map { finding in
                        SARIFResult(
                            ruleId: finding.ruleId,
                            level: severityToLevel(finding.severity),
                            message: SARIFMessage(text: finding.description),
                            locations: [
                                SARIFLocation(
                                    physicalLocation: SARIFPhysicalLocation(
                                        artifactLocation: SARIFArtifactLocation(uri: finding.filePath),
                                        region: SARIFRegion(
                                            startLine: finding.lineNumber,
                                            startColumn: finding.columnStart,
                                            endColumn: finding.columnEnd
                                        )
                                    )
                                )
                            ],
                            fingerprints: ["secretscanner": finding.fingerprint]
                        )
                    }
                )
            ]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        guard let data = try? encoder.encode(sarif),
              let jsonString = String(data: data, encoding: .utf8) else {
            return "{\"error\": \"Failed to encode SARIF\"}"
        }

        return jsonString
    }

    private func buildRules(from findings: [Finding]) -> [SARIFRule] {
        var seenRules: Set<String> = []
        var rules: [SARIFRule] = []

        for finding in findings {
            guard !seenRules.contains(finding.ruleId) else { continue }
            seenRules.insert(finding.ruleId)

            rules.append(SARIFRule(
                id: finding.ruleId,
                name: finding.ruleId,
                shortDescription: SARIFMessage(text: finding.description),
                defaultConfiguration: SARIFDefaultConfiguration(level: severityToLevel(finding.severity))
            ))
        }

        return rules
    }

    private func severityToLevel(_ severity: Severity) -> String {
        switch severity {
        case .critical, .high: return "error"
        case .medium: return "warning"
        case .low, .info: return "note"
        }
    }
}

// SARIF Types
private struct SARIFOutput: Codable {
    let version: String
    let schema: String
    let runs: [SARIFRun]

    enum CodingKeys: String, CodingKey {
        case version
        case schema = "$schema"
        case runs
    }
}

private struct SARIFRun: Codable {
    let tool: SARIFTool
    let results: [SARIFResult]
}

private struct SARIFTool: Codable {
    let driver: SARIFDriver
}

private struct SARIFDriver: Codable {
    let name: String
    let version: String
    let informationUri: String
    let rules: [SARIFRule]
}

private struct SARIFRule: Codable {
    let id: String
    let name: String
    let shortDescription: SARIFMessage
    let defaultConfiguration: SARIFDefaultConfiguration
}

private struct SARIFDefaultConfiguration: Codable {
    let level: String
}

private struct SARIFResult: Codable {
    let ruleId: String
    let level: String
    let message: SARIFMessage
    let locations: [SARIFLocation]
    let fingerprints: [String: String]
}

private struct SARIFMessage: Codable {
    let text: String
}

private struct SARIFLocation: Codable {
    let physicalLocation: SARIFPhysicalLocation
}

private struct SARIFPhysicalLocation: Codable {
    let artifactLocation: SARIFArtifactLocation
    let region: SARIFRegion
}

private struct SARIFArtifactLocation: Codable {
    let uri: String
}

private struct SARIFRegion: Codable {
    let startLine: Int
    let startColumn: Int
    let endColumn: Int
}

// MARK: - Compact Formatter

public struct CompactFormatter: OutputFormatter {

    public init() {}

    public func format(_ result: ScanResult, verbose: Bool) -> String {
        if result.findings.isEmpty {
            return "No secrets found."
        }

        var lines: [String] = []

        for finding in result.findings {
            let line = "\(finding.filePath):\(finding.lineNumber):\(finding.columnStart): [\(finding.severity.rawValue.uppercased())] \(finding.ruleId) - \(finding.secret)"
            lines.append(line)
        }

        lines.append("")
        lines.append("Found \(result.findings.count) secret(s) in \(result.scannedFiles) file(s)")

        return lines.joined(separator: "\n")
    }
}
