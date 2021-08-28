// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "swift-ldap",
    products: [
        .library(
            name: "SwiftLDAP",
            targets: ["SwiftLDAP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.18.0")
    ],
    targets: [
        .systemLibrary(name: "OpenLDAP"),
        .target(
            name: "SwiftLDAP",
            dependencies: [
                "OpenLDAP"
            ]),
        .testTarget(
            name: "SwiftLDAPTests",
            dependencies: ["SwiftLDAP"]),
    ]
)

