// swift-tools-version: 5.5
// SABLE iOS Swift Package

import PackageDescription

fatalError("SABLE mobile packages are withdrawn (SBL-RT-004/008); no Swift package may be built from this implementation.")

let package = Package(
    name: "SABLE",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "SABLE",
            targets: ["SABLE"]
        ),
    ],
    dependencies: [
        // No external dependencies - self-contained
    ],
    targets: [
        .target(
            name: "SABLE",
            dependencies: ["SableCCore"],
            path: "Sources/SABLE"
        ),
        .target(
            name: "SableCCore",
            path: "Sources/SableCCore",
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .define("SABLE_IOS")
            ],
            linkerSettings: [
                .linkedLibrary("System"),
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication")
            ]
        ),
        .testTarget(
            name: "SABLETests",
            dependencies: ["SABLE"],
            path: "Tests/SABLETests"
        ),
    ]
)
