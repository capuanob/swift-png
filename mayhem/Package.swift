// swift-tools-version:5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Newer version of the package manager define a linker symbol for main, which does not exist
// Therefore, we are constrained to SPM <= 5.4

import PackageDescription

let package = Package(
        name: "FuzzTesting",
        dependencies: [
            .package(name: "PNG", path: ".."),
        ],
        targets: [
            .executableTarget(
                    name: "PNGFuzz",
                    dependencies: ["PNG"]
            )
        ]
)