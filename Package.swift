// swift-tools-version: 5.9
import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let package = Package(
    name: "CipherDesk",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CipherDesk", targets: ["CipherDesk"]),
        .executable(name: "CryptoSelfTests", targets: ["CryptoSelfTests"])
    ],
    targets: [
        .target(name: "CryptoBridge", cSettings: [
            .unsafeFlags(["-I", root + "/Vendor/openssl/include"])
        ], linkerSettings: [
            .unsafeFlags([root + "/Vendor/openssl/lib/libcrypto.a"])
        ]),
        .target(name: "CryptoCore", dependencies: ["CryptoBridge"]),
        .executableTarget(name: "CipherDesk", dependencies: ["CryptoCore"]),
        .executableTarget(name: "CryptoSelfTests", dependencies: ["CryptoCore"], path: "Tests/CryptoCoreTests")
    ]
)
