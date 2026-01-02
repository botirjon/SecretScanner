import Foundation
import ArgumentParser
import SecretScannerCore

@main
struct SecretScannerCLI: AsyncParsableCommand {
    
    static let configuration = CommandConfiguration(
        commandName: "secretscanner",
        abstract: "Scan code repositories for secrets and sensitive data",
        version: "1.0.0",
        subcommands: [Scan.self, Init.self, ListRules.self, InstallHook.self, UninstallHook.self],
        defaultSubcommand: Scan.self
    )
}

// MARK: - Scan Command

struct Scan: AsyncParsableCommand {
    
    static let configuration = CommandConfiguration(
        abstract: "Scan a directory or files for secrets"
    )
    
    @Argument(help: "Paths to scan (defaults to current directory)")
    var paths: [String] = []
    
    @Option(name: .shortAndLong, help: "Configuration file path")
    var config: String?
    
    @Option(name: .shortAndLong, help: "Output format: console, json, sarif, compact")
    var format: String = "console"
    
    @Option(name: .shortAndLong, help: "Output file (defaults to stdout)")
    var output: String?
    
    @Option(name: .long, help: "Minimum severity: critical, high, medium, low, info")
    var minSeverity: String = "low"
    
    @Flag(name: .shortAndLong, help: "Show verbose output")
    var verbose: Bool = false
    
    @Flag(name: .long, help: "Disable entropy-based detection")
    var noEntropy: Bool = false
    
    @Flag(name: .long, inversion: .prefixedNo, help: "Exit with error code if secrets are found")
    var failOnSecrets: Bool = true
    
    @Option(name: .long, parsing: .upToNextOption, help: "Rules to disable")
    var disableRules: [String] = []
    
    func run() async throws {
        // Load configuration
        var configuration = try ConfigurationLoader.load(from: config)
        
        // Override with CLI arguments
        if !paths.isEmpty {
            configuration.paths = paths
        }
        
        if let severity = Severity(rawValue: minSeverity) {
            configuration.minSeverity = severity
        }
        
        if noEntropy {
            configuration.enableEntropy = false
        }
        
        configuration.disabledRules.formUnion(disableRules)
        
        // Create scanner
        let scanner = SecretScanner(configuration: configuration)
        
        // Run scan
        if verbose {
            print("🔍 Starting scan...".bold)
        }
        
        let result = await scanner.scan()
        
        // Format output
        let formatter = getFormatter(for: format)
        let formattedOutput = formatter.format(result, verbose: verbose)
        
        // Write output
        if let outputPath = output {
            try formattedOutput.write(toFile: outputPath, atomically: true, encoding: .utf8)
            if verbose {
                print("📝 Results written to: \(outputPath)")
            }
        } else {
            print(formattedOutput)
        }
        
        // Exit code
        if failOnSecrets && result.hasSecrets {
            throw ExitCode(result.exitCode)
        }
    }
    
    private func getFormatter(for format: String) -> OutputFormatter {
        switch format.lowercased() {
        case "json":
            return JSONFormatter()
        case "sarif":
            return SARIFFormatter()
        case "compact":
            return CompactFormatter()
        default:
            return ConsoleFormatter()
        }
    }
}

// MARK: - Init Command

struct Init: ParsableCommand {
    
    static let configuration = CommandConfiguration(
        abstract: "Generate a sample configuration file"
    )
    
    @Option(name: .shortAndLong, help: "Output file path")
    var output: String = ".secretscanner.yml"
    
    @Flag(name: .shortAndLong, help: "Overwrite existing file")
    var force: Bool = false
    
    func run() throws {
        let fileManager = FileManager.default
        
        if fileManager.fileExists(atPath: output) && !force {
            print("❌ File already exists: \(output)")
            print("   Use --force to overwrite")
            throw ExitCode.failure
        }
        
        let config = ConfigurationLoader.generateSampleConfig()
        try config.write(toFile: output, atomically: true, encoding: .utf8)
        
        print("✅ Created configuration file: \(output)")
    }
}

// MARK: - List Rules Command

struct ListRules: ParsableCommand {
    
    static let configuration = CommandConfiguration(
        commandName: "list-rules",
        abstract: "List all available detection rules"
    )
    
    @Flag(name: .shortAndLong, help: "Output as JSON")
    var json: Bool = false
    
    func run() throws {
        let rules = BuiltInRules.allRules()
        
        if json {
            let ruleList = rules.map { rule in
                [
                    "id": rule.id,
                    "description": rule.description,
                    "severity": rule.severity.rawValue,
                    "category": rule.category.rawValue
                ]
            }
            
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            
            if let data = try? encoder.encode(ruleList),
               let jsonString = String(data: data, encoding: .utf8) {
                print(jsonString)
            }
        } else {
            print("\n📋 Available Rules (\(rules.count))\n")
            print(String(repeating: "─", count: 80))
            
            let grouped = Dictionary(grouping: rules, by: { $0.category })
            
            for category in SecretCategory.allCases {
                guard let categoryRules = grouped[category], !categoryRules.isEmpty else {
                    continue
                }
                
                print("\n\(category.rawValue.uppercased())".bold)
                
                for rule in categoryRules.sorted(by: { $0.id < $1.id }) {
                    let severity = rule.severity.emoji
                    print("  \(severity) \(rule.id)")
                    print("      \(rule.description.dim)")
                }
            }
            
            print("\n" + String(repeating: "─", count: 80))
            print("Total: \(rules.count) rules\n")
        }
    }
}

// MARK: - Install Hook Command

struct InstallHook: ParsableCommand {

    static let configuration = CommandConfiguration(
        commandName: "install-hook",
        abstract: "Install a git pre-commit hook to scan for secrets"
    )

    @Option(name: .shortAndLong, help: "Repository path (defaults to current directory)")
    var path: String = "."

    @Flag(name: .shortAndLong, help: "Overwrite existing hook")
    var force: Bool = false

    func run() throws {
        let gitHelper = GitHelper()
        let result = gitHelper.installPreCommitHook(at: path, force: force)

        switch result {
        case .success(let hookPath):
            print("✅ Pre-commit hook installed: \(hookPath)")
            print("")
            print("The hook will automatically scan staged files for secrets before each commit.")
            print("To skip the check, use: git commit --no-verify")
        case .failure(let error):
            print("❌ \(error.localizedDescription)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Uninstall Hook Command

struct UninstallHook: ParsableCommand {

    static let configuration = CommandConfiguration(
        commandName: "uninstall-hook",
        abstract: "Remove the SecretScanner pre-commit hook"
    )

    @Option(name: .shortAndLong, help: "Repository path (defaults to current directory)")
    var path: String = "."

    func run() throws {
        let gitHelper = GitHelper()
        let result = gitHelper.uninstallPreCommitHook(at: path)

        switch result {
        case .success:
            print("✅ Pre-commit hook removed successfully")
        case .failure(let error):
            print("❌ \(error.localizedDescription)")
            throw ExitCode.failure
        }
    }
}
