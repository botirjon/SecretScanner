// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SecretScanner",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "secretscanner",
            targets: ["SecretScanner"]
        ),
        .library(
            name: "SecretScannerCore",
            targets: ["SecretScannerCore"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.0.0"),
        .package(url: "https://github.com/onevcat/Rainbow.git", from: "4.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "SecretScanner",
            dependencies: [
                "SecretScannerCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        ),
        .target(
            name: "SecretScannerCore",
            dependencies: [
                "Yams",
                "Rainbow",
            ]
        ),
        .testTarget(
            name: "SecretScannerTests",
            dependencies: ["SecretScannerCore"]
        ),
    ]
)
