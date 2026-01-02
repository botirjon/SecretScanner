# SecretScanner

A fast, configurable secret detection tool written in Swift. Similar to [gitleaks](https://github.com/gitleaks/gitleaks), but native to Swift and designed with iOS/macOS developers in mind.

## Features

- 🔍 **40+ built-in detection rules** for common secrets (AWS, GCP, GitHub, Stripe, etc.)
- 🎯 **iOS-specific rules** for App Store Connect, APNs keys, CocoaPods tokens
- 📊 **Entropy-based detection** for random high-entropy strings
- ⚡ **Fast concurrent scanning** with configurable parallelism
- 🎨 **Multiple output formats**: Console, JSON, SARIF (for CI integration)
- 🔧 **Highly configurable** via YAML/JSON config files
- 📝 **Allowlisting** to handle false positives
- 🪝 **Git integration** with pre-commit hook support

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/botirjon/SecretScanner", from: "1.0.0")
]
```

### Build from Source

```bash
git clone https://github.com/botirjon/SecretScanner.git
cd SecretScanner
swift build -c release
cp .build/release/secretscanner /usr/local/bin/
```

## Usage

### Basic Scan

```bash
# Scan current directory
secretscanner scan

# Scan specific paths
secretscanner scan ./Sources ./Config

# Scan with verbose output
secretscanner scan --verbose
```

### Output Formats

```bash
# Console output (default)
secretscanner scan

# JSON output
secretscanner scan --format json --output results.json

# SARIF output (for GitHub/GitLab CI)
secretscanner scan --format sarif --output results.sarif

# Compact output (one line per finding)
secretscanner scan --format compact
```

### Configuration

Generate a sample configuration file:

```bash
secretscanner init
```

This creates `.secretscanner.yml`:

```yaml
# Paths to scan
paths:
  - .

# Paths to ignore (glob patterns)
ignorePaths:
  - "**/*Test*.swift"
  - "**/Mock/**"
  - "Pods/**"

# Rules to disable
disabledRules:
  - high-entropy-string

# Minimum severity to report
minSeverity: low

# Allowlist known false positives
allowlist:
  - fingerprint: "abc123..."
    reason: "Test fixture"
  - ruleId: "generic-password"
    path: "Tests/"
    reason: "Test passwords"

# Custom rules
customRules:
  - id: my-internal-key
    description: "Internal API Key"
    pattern: "MYCOMPANY_[A-Z0-9]{32}"
    severity: high
    category: api-key
```

### List Available Rules

```bash
# Console output
secretscanner list-rules

# JSON output
secretscanner list-rules --json
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build SecretScanner
        run: |
          git clone https://github.com/botirjon/SecretScanner.git
          cd SecretScanner && swift build -c release
          
      - name: Run Secret Scan
        run: |
          ./SecretScanner/.build/release/secretscanner scan \
            --format sarif \
            --output results.sarif
            
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
secret-scan:
  stage: test
  script:
    - swift build -c release
    - .build/release/secretscanner scan --format compact
  allow_failure: false
```

### Git Pre-commit Hook

Install automatically:

```bash
secretscanner install-hook
```

Or manually create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
secretscanner scan $(git diff --cached --name-only --diff-filter=ACMR) --format compact
```

## Supported Secrets

### Cloud Providers
- AWS Access Key ID, Secret Access Key, MWS Auth Token
- Google Cloud API Key, Service Account, OAuth Client Secret
- Azure Storage Key, Connection String, Client Secret
- Firebase API Key

### Tokens & API Keys
- GitHub Personal Access Token, OAuth, App Token
- GitLab Personal Access Token
- Slack Token, Webhook URL
- Stripe API Key
- Twilio API Key
- SendGrid API Key
- OpenAI API Key
- Anthropic API Key
- NPM Token
- PyPI Token
- Telegram Bot Token
- Discord Bot Token
- JWT Tokens

### Private Keys
- RSA Private Key
- OpenSSH Private Key
- EC Private Key
- PGP Private Key

### Database Connection Strings
- MySQL
- PostgreSQL
- MongoDB
- Redis

### iOS Specific
- App Store Connect API Key
- Apple P8 Private Key (APNs)
- APNs Key ID
- Provisioning Profile UUID
- Keychain Passwords
- CocoaPods Trunk Token

### Generic
- Passwords in variable assignments
- Basic Auth Headers
- Bearer Tokens
- Hardcoded URL Credentials
- High-entropy strings (configurable threshold)

## Library Usage

Use SecretScanner as a library in your Swift project:

```swift
import SecretScannerCore

// Create configuration
var config = Configuration()
config.paths = ["./Sources"]
config.minSeverity = .high
config.disabledRules = ["high-entropy-string"]

// Create scanner
let scanner = SecretScanner(configuration: config)

// Run scan
let result = await scanner.scan()

// Process results
for finding in result.findings {
    print("\(finding.filePath):\(finding.lineNumber) - \(finding.description)")
}

// Check exit code
if result.hasSecrets {
    print("Found \(result.findings.count) secrets!")
}
```

## Adding Custom Rules

### Via Configuration

```yaml
customRules:
  - id: my-company-api-key
    description: "MyCompany API Key"
    pattern: "MC_[A-Za-z0-9]{32}"
    severity: critical
    category: api-key
    keywords:
      - MC_
```

### Programmatically

```swift
let customRule = try RegexRule(
    id: "my-custom-rule",
    description: "My Custom Secret",
    pattern: #"CUSTOM_[A-Z0-9]{16}"#,
    severity: .high,
    category: .apiKey,
    keywords: ["CUSTOM_"]
)
```

## Performance

SecretScanner uses several optimizations:

1. **Keyword pre-filtering**: Rules with keywords skip regex matching if no keyword is present
2. **Concurrent scanning**: Files are scanned in parallel (configurable concurrency)
3. **Streaming file processing**: Large files are processed line-by-line
4. **Early termination**: Skips binary files and files exceeding size limits

Typical performance on a medium-sized iOS project (~1000 Swift files):
- Cold scan: ~2-3 seconds
- With keyword pre-filtering: ~1-2 seconds

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Adding New Rules

1. Add the rule pattern to `BuiltInRules.swift`
2. Add tests in `SecretScannerTests.swift`
3. Update this README with the new secret type

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Inspired by:
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/truffleHog)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
