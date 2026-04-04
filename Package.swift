// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "BSV",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(name: "BSV", targets: ["BSV"])
    ],
    targets: [
        .target(
            name: "BSV",
            path: "Sources/BSV"
        ),
        .testTarget(
            name: "BSVTests",
            dependencies: ["BSV"],
            path: "Tests/BSVTests"
        )
    ]
)
