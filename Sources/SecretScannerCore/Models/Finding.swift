import Foundation

// MARK: - Finding

public struct Finding: Sendable, Codable {
    public let ruleId: String
    public let description: String
    public let severity: Severity
    public let category: SecretCategory
    public let filePath: String
    public let lineNumber: Int
    public let columnStart: Int
    public let columnEnd: Int
    public let line: String
    public let secret: String
    public let fingerprint: String

    public init(
        ruleId: String,
        description: String,
        severity: Severity,
        category: SecretCategory,
        filePath: String,
        lineNumber: Int,
        columnStart: Int,
        columnEnd: Int,
        line: String,
        secret: String,
        fingerprint: String
    ) {
        self.ruleId = ruleId
        self.description = description
        self.severity = severity
        self.category = category
        self.filePath = filePath
        self.lineNumber = lineNumber
        self.columnStart = columnStart
        self.columnEnd = columnEnd
        self.line = line
        self.secret = secret
        self.fingerprint = fingerprint
    }
}

// MARK: - ScanResult

public struct ScanResult: Sendable {
    public let findings: [Finding]
    public let scannedFiles: Int
    public let scannedLines: Int
    public let duration: TimeInterval
    public let errors: [ScanError]

    public var hasSecrets: Bool {
        !findings.isEmpty
    }

    public var exitCode: Int32 {
        hasSecrets ? 1 : 0
    }

    public init(
        findings: [Finding],
        scannedFiles: Int,
        scannedLines: Int,
        duration: TimeInterval,
        errors: [ScanError]
    ) {
        self.findings = findings
        self.scannedFiles = scannedFiles
        self.scannedLines = scannedLines
        self.duration = duration
        self.errors = errors
    }
}

// MARK: - ScanError

public struct ScanError: Sendable, Error {
    public let file: String
    public let message: String

    public init(file: String, message: String) {
        self.file = file
        self.message = message
    }
}
