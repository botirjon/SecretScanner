import Foundation

// MARK: - Git Helper

public struct GitHelper {

    private let fileManager: FileManager

    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    // MARK: - Hook Installation

    /// Installs a pre-commit hook that runs SecretScanner
    /// - Parameters:
    ///   - path: The repository path (defaults to current directory)
    ///   - force: Whether to overwrite an existing hook
    /// - Returns: Result indicating success or failure
    public func installPreCommitHook(at path: String = ".", force: Bool = false) -> Result<String, GitError> {
        let repoPath = resolveAbsolutePath(path)
        let gitDir = (repoPath as NSString).appendingPathComponent(".git")
        let hooksDir = (gitDir as NSString).appendingPathComponent("hooks")
        let hookPath = (hooksDir as NSString).appendingPathComponent("pre-commit")

        // Check if .git directory exists
        guard fileManager.fileExists(atPath: gitDir) else {
            return .failure(.notAGitRepository(repoPath))
        }

        // Create hooks directory if it doesn't exist
        if !fileManager.fileExists(atPath: hooksDir) {
            do {
                try fileManager.createDirectory(atPath: hooksDir, withIntermediateDirectories: true)
            } catch {
                return .failure(.unableToCreateHooksDirectory(error.localizedDescription))
            }
        }

        // Check for existing hook
        if fileManager.fileExists(atPath: hookPath) && !force {
            return .failure(.hookAlreadyExists(hookPath))
        }

        // Write hook script
        let hookScript = generatePreCommitHookScript()

        do {
            try hookScript.write(toFile: hookPath, atomically: true, encoding: .utf8)
        } catch {
            return .failure(.unableToWriteHook(error.localizedDescription))
        }

        // Make hook executable
        do {
            try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hookPath)
        } catch {
            return .failure(.unableToSetPermissions(error.localizedDescription))
        }

        return .success(hookPath)
    }

    /// Uninstalls the SecretScanner pre-commit hook
    /// - Parameter path: The repository path (defaults to current directory)
    /// - Returns: Result indicating success or failure
    public func uninstallPreCommitHook(at path: String = ".") -> Result<Void, GitError> {
        let repoPath = resolveAbsolutePath(path)
        let gitDir = (repoPath as NSString).appendingPathComponent(".git")
        let hooksDir = (gitDir as NSString).appendingPathComponent("hooks")
        let hookPath = (hooksDir as NSString).appendingPathComponent("pre-commit")

        guard fileManager.fileExists(atPath: hookPath) else {
            return .failure(.hookNotFound(hookPath))
        }

        // Verify it's our hook before removing
        if let content = fileManager.contents(atPath: hookPath),
           let script = String(data: content, encoding: .utf8),
           !script.contains("secretscanner") {
            return .failure(.hookNotOurs(hookPath))
        }

        do {
            try fileManager.removeItem(atPath: hookPath)
        } catch {
            return .failure(.unableToRemoveHook(error.localizedDescription))
        }

        return .success(())
    }

    /// Checks if a SecretScanner pre-commit hook is installed
    /// - Parameter path: The repository path (defaults to current directory)
    /// - Returns: True if hook is installed
    public func isHookInstalled(at path: String = ".") -> Bool {
        let repoPath = resolveAbsolutePath(path)
        let gitDir = (repoPath as NSString).appendingPathComponent(".git")
        let hooksDir = (gitDir as NSString).appendingPathComponent("hooks")
        let hookPath = (hooksDir as NSString).appendingPathComponent("pre-commit")

        guard fileManager.fileExists(atPath: hookPath),
              let content = fileManager.contents(atPath: hookPath),
              let script = String(data: content, encoding: .utf8) else {
            return false
        }

        return script.contains("secretscanner")
    }

    // MARK: - Staged Files

    /// Gets the list of staged files for the current commit
    /// - Parameter path: The repository path
    /// - Returns: Array of staged file paths
    public func getStagedFiles(at path: String = ".") -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["diff", "--cached", "--name-only", "--diff-filter=ACMR"]
        process.currentDirectoryURL = URL(fileURLWithPath: resolveAbsolutePath(path))

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else {
                return []
            }

            return output
                .components(separatedBy: .newlines)
                .filter { !$0.isEmpty }
        } catch {
            return []
        }
    }

    // MARK: - Private Helpers

    private func resolveAbsolutePath(_ path: String) -> String {
        if path.hasPrefix("/") {
            return path
        }
        return (fileManager.currentDirectoryPath as NSString).appendingPathComponent(path)
    }

    private func generatePreCommitHookScript() -> String {
        """
        #!/bin/bash
        # SecretScanner pre-commit hook
        # Automatically installed by: secretscanner install-hook

        # Get the list of staged files
        STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

        if [ -z "$STAGED_FILES" ]; then
            exit 0
        fi

        # Check if secretscanner is available
        if ! command -v secretscanner &> /dev/null; then
            echo "Warning: secretscanner not found in PATH"
            echo "Install it or add it to your PATH to enable secret scanning"
            exit 0
        fi

        echo "Running SecretScanner on staged files..."

        # Run secretscanner on staged files
        secretscanner scan $STAGED_FILES --format compact

        RESULT=$?

        if [ $RESULT -ne 0 ]; then
            echo ""
            echo "SecretScanner found potential secrets in your commit!"
            echo "Please review and remove any secrets before committing."
            echo ""
            echo "If these are false positives, you can:"
            echo "  1. Add them to your .secretscanner.yml allowlist"
            echo "  2. Skip this check with: git commit --no-verify"
            echo ""
            exit 1
        fi

        exit 0
        """
    }
}

// MARK: - Git Errors

public enum GitError: Error, LocalizedError {
    case notAGitRepository(String)
    case hookAlreadyExists(String)
    case hookNotFound(String)
    case hookNotOurs(String)
    case unableToCreateHooksDirectory(String)
    case unableToWriteHook(String)
    case unableToSetPermissions(String)
    case unableToRemoveHook(String)

    public var errorDescription: String? {
        switch self {
        case .notAGitRepository(let path):
            return "Not a git repository: \(path)"
        case .hookAlreadyExists(let path):
            return "Pre-commit hook already exists: \(path)\nUse --force to overwrite"
        case .hookNotFound(let path):
            return "Pre-commit hook not found: \(path)"
        case .hookNotOurs(let path):
            return "Existing hook was not installed by SecretScanner: \(path)\nManually remove it or use --force"
        case .unableToCreateHooksDirectory(let message):
            return "Unable to create hooks directory: \(message)"
        case .unableToWriteHook(let message):
            return "Unable to write hook: \(message)"
        case .unableToSetPermissions(let message):
            return "Unable to set hook permissions: \(message)"
        case .unableToRemoveHook(let message):
            return "Unable to remove hook: \(message)"
        }
    }
}
