import Foundation

// MARK: - Severity

public enum Severity: String, Comparable, Sendable, Codable {
    case info
    case low
    case medium
    case high
    case critical

    private var order: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.order < rhs.order
    }

    public var emoji: String {
        switch self {
        case .info: return "ℹ️"
        case .low: return "🟢"
        case .medium: return "🟡"
        case .high: return "🟠"
        case .critical: return "🔴"
        }
    }
}

// MARK: - Secret Category

public enum SecretCategory: String, Sendable, Codable {
    case cloudProvider = "cloud-provider"
    case apiKey = "api-key"
    case token = "token"
    case privateKey = "private-key"
    case connectionString = "connection-string"
    case password = "password"
    case credential = "credential"
    case certificate = "certificate"
    case generic = "generic"
}

// MARK: - Rule Protocol

public protocol Rule: Sendable {
    var id: String { get }
    var description: String { get }
    var severity: Severity { get }
    var category: SecretCategory { get }
    var keywords: [String] { get }

    func detect(in line: String, lineNumber: Int, filePath: String) -> [Finding]
}

// MARK: - RegexRule

public struct RegexRule: Rule {
    public let id: String
    public let description: String
    public let severity: Severity
    public let category: SecretCategory
    public let keywords: [String]

    private let pattern: String
    private let regex: NSRegularExpression
    private let secretGroupIndex: Int
    private let caseSensitive: Bool

    public init(
        id: String,
        description: String,
        pattern: String,
        severity: Severity,
        category: SecretCategory,
        keywords: [String] = [],
        secretGroupIndex: Int = 0,
        caseSensitive: Bool = true
    ) throws {
        self.id = id
        self.description = description
        self.pattern = pattern
        self.severity = severity
        self.category = category
        self.keywords = keywords
        self.secretGroupIndex = secretGroupIndex
        self.caseSensitive = caseSensitive

        var options: NSRegularExpression.Options = []
        if !caseSensitive {
            options.insert(.caseInsensitive)
        }

        self.regex = try NSRegularExpression(pattern: pattern, options: options)
    }

    public func detect(in line: String, lineNumber: Int, filePath: String) -> [Finding] {
        var findings: [Finding] = []

        let range = NSRange(line.startIndex..., in: line)
        let matches = regex.matches(in: line, options: [], range: range)

        for match in matches {
            let matchRange: NSRange
            if secretGroupIndex > 0 && secretGroupIndex < match.numberOfRanges {
                matchRange = match.range(at: secretGroupIndex)
            } else {
                matchRange = match.range
            }

            guard matchRange.location != NSNotFound,
                  let swiftRange = Range(matchRange, in: line) else {
                continue
            }

            let secret = String(line[swiftRange])
            let maskedSecret = maskSecret(secret)

            let finding = Finding(
                ruleId: id,
                description: description,
                severity: severity,
                category: category,
                filePath: filePath,
                lineNumber: lineNumber,
                columnStart: matchRange.location + 1,
                columnEnd: matchRange.location + matchRange.length,
                line: line,
                secret: maskedSecret,
                fingerprint: generateFingerprint(filePath: filePath, lineNumber: lineNumber, ruleId: id, secret: secret)
            )

            findings.append(finding)
        }

        return findings
    }

    private func maskSecret(_ secret: String) -> String {
        guard secret.count > 8 else {
            return String(repeating: "*", count: secret.count)
        }

        let prefix = String(secret.prefix(4))
        let suffix = String(secret.suffix(4))
        let masked = String(repeating: "*", count: min(secret.count - 8, 20))

        return "\(prefix)\(masked)\(suffix)"
    }

    private func generateFingerprint(filePath: String, lineNumber: Int, ruleId: String, secret: String) -> String {
        let input = "\(filePath):\(lineNumber):\(ruleId):\(secret)"

        // Simple hash for fingerprint
        var hash: UInt64 = 5381
        for byte in input.utf8 {
            hash = ((hash << 5) &+ hash) &+ UInt64(byte)
        }

        return String(format: "%016llx", hash)
    }
}

// MARK: - EntropyRule

public struct EntropyRule: Rule {
    public let id: String = "high-entropy-string"
    public let description: String = "High entropy string (possible secret)"
    public let severity: Severity = .medium
    public let category: SecretCategory = .generic
    public let keywords: [String] = []

    private let minLength: Int
    private let entropyThreshold: Double
    private let regex: NSRegularExpression

    public init(minLength: Int = 20, entropyThreshold: Double = 4.5) throws {
        self.minLength = minLength
        self.entropyThreshold = entropyThreshold

        // Match potential secret strings (alphanumeric with some special chars)
        self.regex = try NSRegularExpression(
            pattern: #"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]"#,
            options: []
        )
    }

    public func detect(in line: String, lineNumber: Int, filePath: String) -> [Finding] {
        var findings: [Finding] = []

        let range = NSRange(line.startIndex..., in: line)
        let matches = regex.matches(in: line, options: [], range: range)

        for match in matches {
            guard match.numberOfRanges > 1 else { continue }

            let secretRange = match.range(at: 1)
            guard secretRange.location != NSNotFound,
                  let swiftRange = Range(secretRange, in: line) else {
                continue
            }

            let potentialSecret = String(line[swiftRange])

            // Skip if it looks like a common non-secret pattern
            if isLikelyNotSecret(potentialSecret) {
                continue
            }

            let entropy = calculateEntropy(potentialSecret)

            if entropy >= entropyThreshold {
                let maskedSecret = maskSecret(potentialSecret)

                let finding = Finding(
                    ruleId: id,
                    description: "\(description) (entropy: \(String(format: "%.2f", entropy)))",
                    severity: severity,
                    category: category,
                    filePath: filePath,
                    lineNumber: lineNumber,
                    columnStart: secretRange.location + 1,
                    columnEnd: secretRange.location + secretRange.length,
                    line: line,
                    secret: maskedSecret,
                    fingerprint: generateFingerprint(filePath: filePath, lineNumber: lineNumber, secret: potentialSecret)
                )

                findings.append(finding)
            }
        }

        return findings
    }

    private func calculateEntropy(_ string: String) -> Double {
        var frequency: [Character: Int] = [:]

        for char in string {
            frequency[char, default: 0] += 1
        }

        let length = Double(string.count)
        var entropy: Double = 0

        for count in frequency.values {
            let probability = Double(count) / length
            entropy -= probability * log2(probability)
        }

        return entropy
    }

    private func isLikelyNotSecret(_ string: String) -> Bool {
        // Skip common patterns that aren't secrets
        let nonSecretPatterns = [
            // Base64 padding
            string.hasSuffix("===="),
            // All same character
            Set(string).count <= 2,
            // Common placeholder patterns
            string.lowercased().contains("example"),
            string.lowercased().contains("placeholder"),
            string.lowercased().contains("xxxxxxxx"),
            // UUIDs (usually not secrets)
            string.contains("-") && string.filter { $0 == "-" }.count == 4,
        ]

        return nonSecretPatterns.contains(true)
    }

    private func maskSecret(_ secret: String) -> String {
        guard secret.count > 8 else {
            return String(repeating: "*", count: secret.count)
        }

        let prefix = String(secret.prefix(4))
        let suffix = String(secret.suffix(4))
        let masked = String(repeating: "*", count: min(secret.count - 8, 20))

        return "\(prefix)\(masked)\(suffix)"
    }

    private func generateFingerprint(filePath: String, lineNumber: Int, secret: String) -> String {
        let input = "\(filePath):\(lineNumber):\(id):\(secret)"

        var hash: UInt64 = 5381
        for byte in input.utf8 {
            hash = ((hash << 5) &+ hash) &+ UInt64(byte)
        }

        return String(format: "%016llx", hash)
    }
}
