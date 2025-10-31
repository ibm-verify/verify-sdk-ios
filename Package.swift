// swift-tools-version: 5.9

// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "IBM Verify",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "FIDO2",
            targets: ["FIDO2"]),
        .library(
            name: "Adaptive",
            targets: ["Adaptive"]),
        .library(
            name: "Core",
            targets: ["Core"]),
        .library(
            name: "Authentication",
            targets: ["Authentication"]),
        .library(
            name: "MFA",
            targets: ["MFA"]),
        .library(
            name: "DC",
            targets: ["DC"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        //.package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "FIDO2",
            path: "Sources/fido2",
            resources: [
                .copy("README.md")
            ]),
        .testTarget(
            name: "FIDO2Tests",
            dependencies: ["FIDO2"],
            path: "Tests/FIDO2Tests",
            resources: [
                .copy("Files")
            ],
            linkerSettings: [
              .linkedFramework(
                "XCTest",
                .when(platforms: [.iOS])),
            ]),
        .target(
            name: "Adaptive",
            path: "Sources/adaptive",
            resources: [
                .copy("README.md")
            ]),
        .testTarget(
            name: "AdaptiveTests",
            dependencies: ["Adaptive"],
            path: "Tests/AdaptiveTests",
            linkerSettings: [
              .linkedFramework(
                "XCTest",
                .when(platforms: [.iOS])),
            ]),
        .target(
            name: "Core",
            path: "Sources/core",
            resources: [
                .copy("README.md")
            ]),
        .testTarget(
            name: "CoreTests",
            dependencies: ["Core"],
            path: "Tests/CoreTests",
            linkerSettings: [
              .linkedFramework(
                "XCTest",
                .when(platforms: [.iOS])),
            ]),
        .target(
            name: "Authentication",
            dependencies: ["Core"],
            path: "Sources/authentication",
            resources: [
                .copy("README.md")
            ]),
        .testTarget(
            name: "AuthenticationTests",
            dependencies: ["Authentication", "Core"],
            path: "Tests/AuthenticationTests",
            linkerSettings: [
              .linkedFramework(
                "XCTest",
                .when(platforms: [.iOS])),
            ]),
        .target(
            name: "MFA",
            dependencies: ["Core", "Authentication"],
            path: "Sources/mfa",
            resources: [
                .copy("README.md")
            ]),
        .testTarget(
            name: "MFATests",
            dependencies: ["MFA", "Core", "Authentication"],
            path: "Tests/MFATests",
            resources: [
                .copy("Files")
            ],
            linkerSettings: [
              .linkedFramework(
                "XCTest",
                .when(platforms: [.iOS])),
            ]),
        .target(
            name: "DC",
            dependencies: ["Core", "Authentication"],
            path: "Sources/dc",
            resources: [
                .copy("README.md")
            ]),
        .testTarget(
            name: "DCTests",
            dependencies: ["DC", "Core", "Authentication"],
            path: "Tests/DCTests",
            resources: [
                .copy("Files")
            ],
            linkerSettings: [
              .linkedFramework(
                "XCTest",
                .when(platforms: [.iOS])),
            ]),
    ]
)
