import Foundation
import SecretScannerCore

// MARK: - SecretCategory CaseIterable

extension SecretCategory: CaseIterable {
    public static var allCases: [SecretCategory] = [
        .cloudProvider, .apiKey, .token, .privateKey,
        .connectionString, .password, .credential, .certificate, .generic
    ]
}

// MARK: - String Extensions for CLI

extension String {
    var bold: String { "\u{001B}[1m\(self)\u{001B}[0m" }
    var dim: String { "\u{001B}[2m\(self)\u{001B}[0m" }
}
