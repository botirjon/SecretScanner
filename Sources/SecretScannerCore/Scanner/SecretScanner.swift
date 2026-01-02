import Foundation

// MARK: - Secret Scanner

public actor SecretScanner {
    
    private let configuration: Configuration
    private let rules: [Rule]
    private let fileManager: FileManager
    
    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
        self.fileManager = FileManager.default
        
        // Build rules list
        var allRules: [Rule] = BuiltInRules.allRules()
        
        // Add custom rules
        for customRule in configuration.customRules {
            if let rule = try? customRule.toRule() {
                allRules.append(rule)
            }
        }
        
        // Filter disabled rules and entropy
        self.rules = allRules.filter { rule in
            if configuration.disabledRules.contains(rule.id) {
                return false
            }
            if !configuration.enableEntropy && rule.id == "high-entropy-string" {
                return false
            }
            return true
        }
    }
    
    // MARK: - Public API
    
    public func scan() async -> ScanResult {
        let startTime = Date()
        var allFindings: [Finding] = []
        var totalFiles = 0
        var totalLines = 0
        var errors: [ScanError] = []
        
        // Collect all files to scan
        let filesToScan = collectFiles()
        
        // Process files concurrently
        await withTaskGroup(of: FileScanResult.self) { group in
            for filePath in filesToScan {
                group.addTask {
                    await self.scanFile(filePath)
                }
            }
            
            for await result in group {
                totalFiles += 1
                totalLines += result.lineCount
                allFindings.append(contentsOf: result.findings)
                if let error = result.error {
                    errors.append(error)
                }
            }
        }
        
        // Filter by allowlist
        let filteredFindings = allFindings.filter { finding in
            !configuration.allowlist.contains { $0.matches(finding) }
        }
        
        // Filter by minimum severity
        let severityFiltered = filteredFindings.filter { finding in
            finding.severity >= configuration.minSeverity
        }
        
        // Sort by severity (critical first) then by file
        let sortedFindings = severityFiltered.sorted { a, b in
            if a.severity != b.severity {
                return a.severity > b.severity
            }
            if a.filePath != b.filePath {
                return a.filePath < b.filePath
            }
            return a.lineNumber < b.lineNumber
        }
        
        let duration = Date().timeIntervalSince(startTime)
        
        return ScanResult(
            findings: sortedFindings,
            scannedFiles: totalFiles,
            scannedLines: totalLines,
            duration: duration,
            errors: errors
        )
    }
    
    public func scanFile(_ path: String) async -> FileScanResult {
        var findings: [Finding] = []
        var lineCount = 0
        
        // Check file size
        guard let attributes = try? fileManager.attributesOfItem(atPath: path),
              let fileSize = attributes[.size] as? Int,
              fileSize <= configuration.maxFileSize else {
            return FileScanResult(findings: [], lineCount: 0, error: nil)
        }
        
        // Read file contents
        guard let data = fileManager.contents(atPath: path),
              let content = String(data: data, encoding: .utf8) else {
            return FileScanResult(
                findings: [],
                lineCount: 0,
                error: ScanError(file: path, message: "Unable to read file")
            )
        }
        
        let lines = content.components(separatedBy: .newlines)
        lineCount = lines.count
        
        // Scan each line
        for (index, line) in lines.enumerated() {
            let lineNumber = index + 1
            
            // Skip empty lines and comments
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || isCommentLine(trimmed, filePath: path) {
                continue
            }
            
            // Apply rules
            for rule in rules {
                // Quick keyword check before expensive regex
                if !rule.keywords.isEmpty {
                    let hasKeyword = rule.keywords.contains { keyword in
                        line.localizedCaseInsensitiveContains(keyword)
                    }
                    if !hasKeyword {
                        continue
                    }
                }
                
                let ruleFindings = rule.detect(in: line, lineNumber: lineNumber, filePath: path)
                findings.append(contentsOf: ruleFindings)
            }
        }
        
        return FileScanResult(findings: findings, lineCount: lineCount, error: nil)
    }
    
    // MARK: - File Collection
    
    private func collectFiles() -> [String] {
        var files: [String] = []
        
        for path in configuration.paths {
            let absolutePath = resolveAbsolutePath(path)
            
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: absolutePath, isDirectory: &isDirectory) else {
                continue
            }
            
            if isDirectory.boolValue {
                files.append(contentsOf: collectFilesFromDirectory(absolutePath))
            } else {
                if shouldScanFile(absolutePath) {
                    files.append(absolutePath)
                }
            }
        }
        
        return files
    }
    
    private func collectFilesFromDirectory(_ directory: String) -> [String] {
        var files: [String] = []
        
        guard let enumerator = fileManager.enumerator(
            at: URL(fileURLWithPath: directory),
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else {
            return files
        }
        
        while let url = enumerator.nextObject() as? URL {
            let path = url.path
            
            // Check if should skip directory
            if let isDirectory = try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory,
               isDirectory {
                if shouldIgnorePath(path) {
                    enumerator.skipDescendants()
                }
                continue
            }
            
            // Check if should scan file
            if shouldScanFile(path) {
                files.append(path)
            }
        }
        
        return files
    }
    
    private func shouldScanFile(_ path: String) -> Bool {
        // Check ignore patterns
        if shouldIgnorePath(path) {
            return false
        }
        
        // Check extension
        let ext = (path as NSString).pathExtension.lowercased()
        if ext.isEmpty {
            // Files without extension (Dockerfile, Makefile, etc.)
            let fileName = (path as NSString).lastPathComponent
            return configuration.extensions.contains(fileName)
        }
        
        return configuration.extensions.contains(ext)
    }
    
    private func shouldIgnorePath(_ path: String) -> Bool {
        let relativePath = makeRelativePath(path)
        
        for pattern in configuration.ignorePaths {
            if matchGlob(pattern: pattern, path: relativePath) {
                return true
            }
        }
        
        return false
    }
    
    private func matchGlob(pattern: String, path: String) -> Bool {
        // Simple glob matching supporting * and **
        var regexPattern = NSRegularExpression.escapedPattern(for: pattern)
        
        // Handle **
        regexPattern = regexPattern.replacingOccurrences(of: "\\*\\*", with: ".*")
        // Handle *
        regexPattern = regexPattern.replacingOccurrences(of: "\\*", with: "[^/]*")
        
        regexPattern = "^" + regexPattern + "$"
        
        guard let regex = try? NSRegularExpression(pattern: regexPattern, options: []) else {
            return false
        }
        
        let range = NSRange(path.startIndex..., in: path)
        return regex.firstMatch(in: path, options: [], range: range) != nil
    }
    
    private func resolveAbsolutePath(_ path: String) -> String {
        if path.hasPrefix("/") {
            return path
        }
        return (fileManager.currentDirectoryPath as NSString).appendingPathComponent(path)
    }
    
    private func makeRelativePath(_ path: String) -> String {
        let currentDir = fileManager.currentDirectoryPath
        if path.hasPrefix(currentDir) {
            var relative = String(path.dropFirst(currentDir.count))
            if relative.hasPrefix("/") {
                relative = String(relative.dropFirst())
            }
            return relative
        }
        return path
    }
    
    // MARK: - Comment Detection
    
    private func isCommentLine(_ line: String, filePath: String) -> Bool {
        let ext = (filePath as NSString).pathExtension.lowercased()
        
        switch ext {
        case "swift", "java", "kt", "kts", "js", "ts", "jsx", "tsx", "go", "c", "cpp", "h", "m", "mm", "cs", "scala", "groovy", "rs":
            return line.hasPrefix("//") || line.hasPrefix("/*") || line.hasPrefix("*")
        case "py", "rb", "sh", "bash", "zsh", "yml", "yaml", "toml":
            return line.hasPrefix("#")
        case "html", "xml":
            return line.hasPrefix("<!--")
        default:
            return false
        }
    }
}

// MARK: - File Scan Result

public struct FileScanResult: Sendable {
    public let findings: [Finding]
    public let lineCount: Int
    public let error: ScanError?
}
