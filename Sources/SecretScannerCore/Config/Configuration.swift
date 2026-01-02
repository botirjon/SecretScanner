import Foundation
import Yams

// MARK: - Configuration

public struct Configuration: Sendable {
    public var paths: [String]
    public var ignorePaths: Set<String>
    public var disabledRules: Set<String>
    public var minSeverity: Severity
    public var enableEntropy: Bool
    public var entropyThreshold: Double
    public var maxFileSize: Int
    public var extensions: Set<String>
    public var allowlist: [AllowlistEntry]
    public var customRules: [CustomRuleConfig]

    public init(
        paths: [String] = ["."],
        ignorePaths: Set<String> = [],
        disabledRules: Set<String> = [],
        minSeverity: Severity = .low,
        enableEntropy: Bool = true,
        entropyThreshold: Double = 4.5,
        maxFileSize: Int = 1_000_000,
        extensions: Set<String>? = nil,
        allowlist: [AllowlistEntry] = [],
        customRules: [CustomRuleConfig] = []
    ) {
        self.paths = paths
        self.ignorePaths = ignorePaths.union(Self.defaultIgnorePaths)
        self.disabledRules = disabledRules
        self.minSeverity = minSeverity
        self.enableEntropy = enableEntropy
        self.entropyThreshold = entropyThreshold
        self.maxFileSize = maxFileSize
        self.extensions = extensions ?? Self.defaultExtensions
        self.allowlist = allowlist
        self.customRules = customRules
    }

    public static let defaultExtensions: Set<String> = [
        // Swift/iOS
        "swift", "m", "mm", "h",
        // Web
        "js", "ts", "jsx", "tsx", "vue", "svelte",
        // Python
        "py",
        // Ruby
        "rb",
        // Go
        "go",
        // Java/Kotlin
        "java", "kt", "kts", "gradle",
        // C/C++
        "c", "cpp", "cc", "cxx", "hpp",
        // C#
        "cs",
        // Rust
        "rs",
        // PHP
        "php",
        // Shell
        "sh", "bash", "zsh",
        // Config
        "json", "yml", "yaml", "toml", "xml", "plist",
        "env", "properties", "ini", "cfg", "conf",
        // Misc
        "sql", "graphql", "tf", "tfvars",
        // No extension files
        "Dockerfile", "Makefile", "Gemfile", "Podfile",
        "Fastfile", "Appfile", "Matchfile", "Gymfile"
    ]

    public static let defaultIgnorePaths: Set<String> = [
        ".git/**",
        "node_modules/**",
        "vendor/**",
        "Pods/**",
        ".build/**",
        "build/**",
        "DerivedData/**",
        "*.xcodeproj/**",
        "*.xcworkspace/**",
        "Carthage/**",
        ".swiftpm/**",
        "Package.resolved",
        "*.lock",
        "*.min.js",
        "*.min.css"
    ]
}

// MARK: - AllowlistEntry

public struct AllowlistEntry: Sendable, Codable {
    public let fingerprint: String?
    public let ruleId: String?
    public let path: String?
    public let reason: String?

    public init(
        fingerprint: String? = nil,
        ruleId: String? = nil,
        path: String? = nil,
        reason: String? = nil
    ) {
        self.fingerprint = fingerprint
        self.ruleId = ruleId
        self.path = path
        self.reason = reason
    }

    public func matches(_ finding: Finding) -> Bool {
        // Match by fingerprint
        if let fingerprint = fingerprint, finding.fingerprint == fingerprint {
            return true
        }

        // Match by rule ID and optional path
        if let ruleId = ruleId, finding.ruleId == ruleId {
            if let path = path {
                return finding.filePath.contains(path)
            }
            return true
        }

        return false
    }
}

// MARK: - CustomRuleConfig

public struct CustomRuleConfig: Sendable, Codable {
    public let id: String
    public let description: String
    public let pattern: String
    public let severity: String
    public let category: String
    public let keywords: [String]?

    public init(
        id: String,
        description: String,
        pattern: String,
        severity: String,
        category: String,
        keywords: [String]? = nil
    ) {
        self.id = id
        self.description = description
        self.pattern = pattern
        self.severity = severity
        self.category = category
        self.keywords = keywords
    }

    public func toRule() throws -> Rule {
        let severityValue = Severity(rawValue: severity.lowercased()) ?? .medium
        let categoryValue = SecretCategory(rawValue: category.lowercased()) ?? .generic

        return try RegexRule(
            id: id,
            description: description,
            pattern: pattern,
            severity: severityValue,
            category: categoryValue,
            keywords: keywords ?? []
        )
    }
}

// MARK: - ConfigurationLoader

public struct ConfigurationLoader {

    public static func load(from path: String?) throws -> Configuration {
        // If specific path provided, load from it
        if let path = path {
            return try loadFromFile(path)
        }

        // Try default paths
        let defaultPaths = [
            ".secretscanner.yml",
            ".secretscanner.yaml",
            ".secretscanner.json",
            "secretscanner.yml",
            "secretscanner.yaml",
            "secretscanner.json"
        ]

        let fileManager = FileManager.default

        for defaultPath in defaultPaths {
            if fileManager.fileExists(atPath: defaultPath) {
                return try loadFromFile(defaultPath)
            }
        }

        // Return default configuration
        return Configuration()
    }

    private static func loadFromFile(_ path: String) throws -> Configuration {
        guard let data = FileManager.default.contents(atPath: path),
              let content = String(data: data, encoding: .utf8) else {
            throw ConfigurationError.unableToReadFile(path)
        }

        if path.hasSuffix(".json") {
            return try loadFromJSON(content)
        } else {
            return try loadFromYAML(content)
        }
    }

    private static func loadFromYAML(_ content: String) throws -> Configuration {
        guard let yaml = try Yams.load(yaml: content) as? [String: Any] else {
            throw ConfigurationError.invalidFormat
        }

        return parseConfiguration(from: yaml)
    }

    private static func loadFromJSON(_ content: String) throws -> Configuration {
        guard let data = content.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ConfigurationError.invalidFormat
        }

        return parseConfiguration(from: json)
    }

    private static func parseConfiguration(from dict: [String: Any]) -> Configuration {
        var config = Configuration()

        if let paths = dict["paths"] as? [String] {
            config.paths = paths
        }

        if let ignorePaths = dict["ignorePaths"] as? [String] {
            config.ignorePaths.formUnion(ignorePaths)
        }

        if let disabledRules = dict["disabledRules"] as? [String] {
            config.disabledRules.formUnion(disabledRules)
        }

        if let minSeverity = dict["minSeverity"] as? String,
           let severity = Severity(rawValue: minSeverity.lowercased()) {
            config.minSeverity = severity
        }

        if let enableEntropy = dict["enableEntropy"] as? Bool {
            config.enableEntropy = enableEntropy
        }

        if let entropyThreshold = dict["entropyThreshold"] as? Double {
            config.entropyThreshold = entropyThreshold
        }

        if let maxFileSize = dict["maxFileSize"] as? Int {
            config.maxFileSize = maxFileSize
        }

        if let extensions = dict["extensions"] as? [String] {
            config.extensions = Set(extensions)
        }

        if let allowlistArray = dict["allowlist"] as? [[String: Any]] {
            config.allowlist = allowlistArray.map { item in
                AllowlistEntry(
                    fingerprint: item["fingerprint"] as? String,
                    ruleId: item["ruleId"] as? String,
                    path: item["path"] as? String,
                    reason: item["reason"] as? String
                )
            }
        }

        if let customRulesArray = dict["customRules"] as? [[String: Any]] {
            config.customRules = customRulesArray.compactMap { item in
                guard let id = item["id"] as? String,
                      let description = item["description"] as? String,
                      let pattern = item["pattern"] as? String,
                      let severity = item["severity"] as? String,
                      let category = item["category"] as? String else {
                    return nil
                }

                return CustomRuleConfig(
                    id: id,
                    description: description,
                    pattern: pattern,
                    severity: severity,
                    category: category,
                    keywords: item["keywords"] as? [String]
                )
            }
        }

        return config
    }

    public static func generateSampleConfig() -> String {
        """
        # SecretScanner Configuration
        # See https://github.com/botirjon/SecretScanner for documentation

        # Paths to scan (relative to config file location)
        paths:
          - .

        # Paths to ignore (glob patterns)
        ignorePaths:
          - "**/*Test*.swift"
          - "**/Mock/**"
          - "**/Fixtures/**"
          - "Pods/**"
          - "Carthage/**"

        # Rules to disable
        disabledRules:
          # - high-entropy-string
          # - jwt-token

        # Minimum severity to report: info, low, medium, high, critical
        minSeverity: low

        # Enable entropy-based detection
        enableEntropy: true

        # Entropy threshold (higher = fewer false positives)
        entropyThreshold: 4.5

        # Maximum file size in bytes (skip larger files)
        maxFileSize: 1000000

        # Allowlist known false positives
        allowlist:
          # By fingerprint (most specific)
          # - fingerprint: "abc123..."
          #   reason: "Test fixture"

          # By rule ID and path
          # - ruleId: "generic-password"
          #   path: "Tests/"
          #   reason: "Test passwords"

        # Custom rules
        customRules:
          # - id: my-internal-key
          #   description: "Internal API Key"
          #   pattern: "MYCOMPANY_[A-Z0-9]{32}"
          #   severity: high
          #   category: api-key
          #   keywords:
          #     - MYCOMPANY_
        """
    }
}

// MARK: - Configuration Errors

public enum ConfigurationError: Error, LocalizedError {
    case unableToReadFile(String)
    case invalidFormat

    public var errorDescription: String? {
        switch self {
        case .unableToReadFile(let path):
            return "Unable to read configuration file: \(path)"
        case .invalidFormat:
            return "Invalid configuration file format"
        }
    }
}
