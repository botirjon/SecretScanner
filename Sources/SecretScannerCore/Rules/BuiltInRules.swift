import Foundation

// MARK: - Built-in Rules Provider

public struct BuiltInRules {
    
    public static func allRules() -> [Rule] {
        var rules: [Rule] = []
        
        // AWS
        rules.append(contentsOf: awsRules())
        
        // Google Cloud
        rules.append(contentsOf: gcpRules())
        
        // Azure
        rules.append(contentsOf: azureRules())
        
        // API Keys & Tokens
        rules.append(contentsOf: apiKeyRules())
        
        // Private Keys
        rules.append(contentsOf: privateKeyRules())
        
        // Database
        rules.append(contentsOf: databaseRules())
        
        // Generic Secrets
        rules.append(contentsOf: genericRules())
        
        // iOS Specific
        rules.append(contentsOf: iosRules())
        
        // Entropy-based detection
        if let entropyRule = try? EntropyRule() {
            rules.append(entropyRule)
        }
        
        return rules
    }
    
    // MARK: - AWS Rules
    
    private static func awsRules() -> [Rule] {
        [
            try? RegexRule(
                id: "aws-access-key-id",
                description: "AWS Access Key ID",
                pattern: #"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"#,
                severity: .critical,
                category: .cloudProvider,
                keywords: ["AKIA", "AWS", "aws_access"]
            ),
            try? RegexRule(
                id: "aws-secret-access-key",
                description: "AWS Secret Access Key",
                pattern: #"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"#,
                severity: .critical,
                category: .cloudProvider,
                keywords: ["aws_secret", "secret_access_key"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "aws-mws-auth-token",
                description: "AWS MWS Auth Token",
                pattern: #"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
                severity: .critical,
                category: .cloudProvider,
                keywords: ["amzn.mws"]
            )
        ].compactMap { $0 }
    }
    
    // MARK: - GCP Rules
    
    private static func gcpRules() -> [Rule] {
        [
            try? RegexRule(
                id: "gcp-api-key",
                description: "Google Cloud API Key",
                pattern: #"AIza[0-9A-Za-z\-_]{35}"#,
                severity: .high,
                category: .cloudProvider,
                keywords: ["AIza", "google", "gcp"]
            ),
            try? RegexRule(
                id: "gcp-service-account",
                description: "Google Cloud Service Account Key",
                pattern: #"\"type\":\s*\"service_account\""#,
                severity: .critical,
                category: .cloudProvider,
                keywords: ["service_account", "private_key_id"]
            ),
            try? RegexRule(
                id: "gcp-oauth-client-secret",
                description: "Google OAuth Client Secret",
                pattern: #"(?i)(?:client_secret|google_client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{24})['\"]?"#,
                severity: .high,
                category: .cloudProvider,
                keywords: ["client_secret"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "firebase-api-key",
                description: "Firebase API Key",
                pattern: #"(?i)(?:firebase|firebaseConfig).*?apiKey['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9_-]{39})['\"]?"#,
                severity: .high,
                category: .cloudProvider,
                keywords: ["firebase", "apiKey"],
                secretGroupIndex: 1
            )
        ].compactMap { $0 }
    }
    
    // MARK: - Azure Rules
    
    private static func azureRules() -> [Rule] {
        [
            try? RegexRule(
                id: "azure-storage-key",
                description: "Azure Storage Account Key",
                pattern: #"(?i)(?:account_key|storage_key|azure_storage_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?"#,
                severity: .critical,
                category: .cloudProvider,
                keywords: ["azure", "storage_key", "account_key"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "azure-connection-string",
                description: "Azure Connection String",
                pattern: #"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"#,
                severity: .critical,
                category: .connectionString,
                keywords: ["DefaultEndpointsProtocol", "AccountKey"]
            ),
            try? RegexRule(
                id: "azure-client-secret",
                description: "Azure Client Secret",
                pattern: #"(?i)(?:azure_client_secret|client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9~._-]{40})['\"]?"#,
                severity: .high,
                category: .cloudProvider,
                keywords: ["azure", "client_secret"],
                secretGroupIndex: 1
            )
        ].compactMap { $0 }
    }
    
    // MARK: - API Key Rules
    
    private static func apiKeyRules() -> [Rule] {
        [
            try? RegexRule(
                id: "github-token",
                description: "GitHub Personal Access Token",
                pattern: #"ghp_[A-Za-z0-9]{36}"#,
                severity: .critical,
                category: .token,
                keywords: ["ghp_", "github"]
            ),
            try? RegexRule(
                id: "github-oauth-token",
                description: "GitHub OAuth Access Token",
                pattern: #"gho_[A-Za-z0-9]{36}"#,
                severity: .critical,
                category: .token,
                keywords: ["gho_"]
            ),
            try? RegexRule(
                id: "github-app-token",
                description: "GitHub App Token",
                pattern: #"(?:ghu|ghs)_[A-Za-z0-9]{36}"#,
                severity: .critical,
                category: .token,
                keywords: ["ghu_", "ghs_"]
            ),
            try? RegexRule(
                id: "github-refresh-token",
                description: "GitHub Refresh Token",
                pattern: #"ghr_[A-Za-z0-9]{36}"#,
                severity: .critical,
                category: .token,
                keywords: ["ghr_"]
            ),
            try? RegexRule(
                id: "gitlab-token",
                description: "GitLab Personal Access Token",
                pattern: #"glpat-[A-Za-z0-9\-_]{20,}"#,
                severity: .critical,
                category: .token,
                keywords: ["glpat-", "gitlab"]
            ),
            try? RegexRule(
                id: "slack-token",
                description: "Slack Token",
                pattern: #"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"#,
                severity: .critical,
                category: .token,
                keywords: ["xoxb", "xoxa", "xoxp", "slack"]
            ),
            try? RegexRule(
                id: "slack-webhook",
                description: "Slack Webhook URL",
                pattern: #"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"#,
                severity: .high,
                category: .token,
                keywords: ["hooks.slack.com"]
            ),
            try? RegexRule(
                id: "stripe-api-key",
                description: "Stripe API Key",
                pattern: #"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"#,
                severity: .critical,
                category: .apiKey,
                keywords: ["sk_live", "sk_test", "stripe"]
            ),
            try? RegexRule(
                id: "twilio-api-key",
                description: "Twilio API Key",
                pattern: #"SK[a-f0-9]{32}"#,
                severity: .high,
                category: .apiKey,
                keywords: ["twilio", "SK"]
            ),
            try? RegexRule(
                id: "sendgrid-api-key",
                description: "SendGrid API Key",
                pattern: #"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"#,
                severity: .high,
                category: .apiKey,
                keywords: ["sendgrid", "SG."]
            ),
            try? RegexRule(
                id: "npm-token",
                description: "NPM Access Token",
                pattern: #"npm_[A-Za-z0-9]{36}"#,
                severity: .high,
                category: .token,
                keywords: ["npm_"]
            ),
            try? RegexRule(
                id: "pypi-token",
                description: "PyPI API Token",
                pattern: #"pypi-[A-Za-z0-9_-]{50,}"#,
                severity: .high,
                category: .token,
                keywords: ["pypi-"]
            ),
            try? RegexRule(
                id: "telegram-bot-token",
                description: "Telegram Bot Token",
                pattern: #"[0-9]+:AA[A-Za-z0-9_-]{33}"#,
                severity: .high,
                category: .token,
                keywords: ["telegram", "bot"]
            ),
            try? RegexRule(
                id: "discord-token",
                description: "Discord Bot Token",
                pattern: #"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"#,
                severity: .high,
                category: .token,
                keywords: ["discord"]
            ),
            try? RegexRule(
                id: "openai-api-key",
                description: "OpenAI API Key",
                pattern: #"sk-[A-Za-z0-9]{48}"#,
                severity: .critical,
                category: .apiKey,
                keywords: ["openai", "sk-"]
            ),
            try? RegexRule(
                id: "anthropic-api-key",
                description: "Anthropic API Key",
                pattern: #"sk-ant-[A-Za-z0-9\-_]{93}"#,
                severity: .critical,
                category: .apiKey,
                keywords: ["anthropic", "sk-ant"]
            ),
            try? RegexRule(
                id: "jwt-token",
                description: "JSON Web Token",
                pattern: #"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"#,
                severity: .medium,
                category: .token,
                keywords: ["eyJ", "jwt", "bearer"]
            )
        ].compactMap { $0 }
    }
    
    // MARK: - Private Key Rules
    
    private static func privateKeyRules() -> [Rule] {
        [
            try? RegexRule(
                id: "rsa-private-key",
                description: "RSA Private Key",
                pattern: #"-----BEGIN RSA PRIVATE KEY-----"#,
                severity: .critical,
                category: .privateKey,
                keywords: ["BEGIN RSA PRIVATE KEY"]
            ),
            try? RegexRule(
                id: "openssh-private-key",
                description: "OpenSSH Private Key",
                pattern: #"-----BEGIN OPENSSH PRIVATE KEY-----"#,
                severity: .critical,
                category: .privateKey,
                keywords: ["BEGIN OPENSSH PRIVATE KEY"]
            ),
            try? RegexRule(
                id: "ec-private-key",
                description: "EC Private Key",
                pattern: #"-----BEGIN EC PRIVATE KEY-----"#,
                severity: .critical,
                category: .privateKey,
                keywords: ["BEGIN EC PRIVATE KEY"]
            ),
            try? RegexRule(
                id: "pgp-private-key",
                description: "PGP Private Key",
                pattern: #"-----BEGIN PGP PRIVATE KEY BLOCK-----"#,
                severity: .critical,
                category: .privateKey,
                keywords: ["BEGIN PGP PRIVATE KEY"]
            ),
            try? RegexRule(
                id: "generic-private-key",
                description: "Private Key",
                pattern: #"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----"#,
                severity: .critical,
                category: .privateKey,
                keywords: ["BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY"]
            )
        ].compactMap { $0 }
    }
    
    // MARK: - Database Rules
    
    private static func databaseRules() -> [Rule] {
        [
            try? RegexRule(
                id: "mysql-connection-string",
                description: "MySQL Connection String",
                pattern: #"mysql://[^:]+:[^@]+@[^/]+/[^\s'\"]+"#,
                severity: .critical,
                category: .connectionString,
                keywords: ["mysql://"]
            ),
            try? RegexRule(
                id: "postgres-connection-string",
                description: "PostgreSQL Connection String",
                pattern: #"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s'\"]+"#,
                severity: .critical,
                category: .connectionString,
                keywords: ["postgres://", "postgresql://"]
            ),
            try? RegexRule(
                id: "mongodb-connection-string",
                description: "MongoDB Connection String",
                pattern: #"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"]+"#,
                severity: .critical,
                category: .connectionString,
                keywords: ["mongodb://", "mongodb+srv://"]
            ),
            try? RegexRule(
                id: "redis-connection-string",
                description: "Redis Connection String",
                pattern: #"redis://[^:]*:[^@]+@[^\s'\"]+"#,
                severity: .high,
                category: .connectionString,
                keywords: ["redis://"]
            )
        ].compactMap { $0 }
    }
    
    // MARK: - Generic Secrets
    
    private static func genericRules() -> [Rule] {
        [
            try? RegexRule(
                id: "generic-password",
                description: "Password in variable assignment",
                pattern: #"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|api-key|auth_token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"#,
                severity: .high,
                category: .password,
                keywords: ["password", "passwd", "secret", "token", "api_key"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "basic-auth-header",
                description: "Basic Auth Header",
                pattern: #"(?i)authorization['\"]?\s*[=:]\s*['\"]?basic\s+[A-Za-z0-9+/=]+"#,
                severity: .high,
                category: .credential,
                keywords: ["authorization", "basic"]
            ),
            try? RegexRule(
                id: "bearer-token-header",
                description: "Bearer Token in Header",
                pattern: #"(?i)authorization['\"]?\s*[=:]\s*['\"]?bearer\s+[A-Za-z0-9._-]+"#,
                severity: .high,
                category: .token,
                keywords: ["authorization", "bearer"]
            ),
            try? RegexRule(
                id: "hardcoded-url-credentials",
                description: "Hardcoded Credentials in URL",
                pattern: #"(?:https?|ftp)://[^:]+:[^@]+@[^\s'\"]+"#,
                severity: .high,
                category: .credential,
                keywords: ["://"]
            )
        ].compactMap { $0 }
    }
    
    // MARK: - iOS Specific Rules
    
    private static func iosRules() -> [Rule] {
        [
            try? RegexRule(
                id: "ios-app-store-connect-key",
                description: "App Store Connect API Key",
                pattern: #"(?i)(?:app_store_connect_api_key|asc_key|issuer_id)\s*[=:]\s*['\"]([A-Za-z0-9\-]{36})['\"]"#,
                severity: .high,
                category: .apiKey,
                keywords: ["app_store_connect", "issuer_id"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "ios-p8-key",
                description: "Apple P8 Private Key",
                pattern: #"-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----"#,
                severity: .critical,
                category: .privateKey,
                keywords: ["BEGIN PRIVATE KEY"]
            ),
            try? RegexRule(
                id: "apns-key-id",
                description: "Apple Push Notification Key ID",
                pattern: #"(?i)(?:apns_key_id|key_id|push_key)\s*[=:]\s*['\"]([A-Z0-9]{10})['\"]"#,
                severity: .medium,
                category: .apiKey,
                keywords: ["apns", "key_id", "push_key"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "ios-provisioning-profile",
                description: "iOS Provisioning Profile UUID",
                pattern: #"(?i)(?:provisioning_profile|profile_uuid)\s*[=:]\s*['\"]([A-F0-9\-]{36})['\"]"#,
                severity: .low,
                category: .credential,
                keywords: ["provisioning_profile", "profile_uuid"],
                secretGroupIndex: 1,
                caseSensitive: true
            ),
            try? RegexRule(
                id: "ios-keychain-service",
                description: "Hardcoded Keychain Password",
                pattern: #"(?i)kSecValueData[^}]*?['\"]([^'\"]{8,})['\"]"#,
                severity: .high,
                category: .password,
                keywords: ["kSecValueData"],
                secretGroupIndex: 1
            ),
            try? RegexRule(
                id: "cocoapods-trunk-token",
                description: "CocoaPods Trunk Token",
                pattern: #"pod_trunk_token\s*[=:]\s*['\"]([A-Za-z0-9]{32})['\"]"#,
                severity: .high,
                category: .token,
                keywords: ["pod_trunk", "cocoapods"],
                secretGroupIndex: 1
            )
        ].compactMap { $0 }
    }
}
