import Foundation

public enum Algorithm: String, CaseIterable, Codable, Identifiable, Sendable {
    case md5 = "MD5", sha256 = "SHA-256", des = "DES", tripleDES = "3DES", aes = "AES", rsa = "RSA", sm2 = "SM2", sm3 = "SM3", sm4 = "SM4"
    public var id: String { rawValue }
    public var isDigest: Bool { [.md5, .sha256, .sm3].contains(self) }
    public var isAsymmetric: Bool { self == .rsa || self == .sm2 }
    public var isSymmetric: Bool { !isDigest && !isAsymmetric }
    public var keyBytes: Int { switch self { case .des: 8; case .tripleDES: 24; case .aes: 32; default: 16 } }
    public var blockBytes: Int { self == .des || self == .tripleDES ? 8 : 16 }
    public var category: String { isDigest ? "摘要算法" : (isAsymmetric ? "非对称加密" : "对称加密") }
    public var detail: String {
        switch self {
        case .md5: "128 位摘要 · 常用于校验与旧接口兼容"
        case .sha256: "256 位摘要 · SHA-2 系列"
        case .des: "64 位分组 · 8 字节密钥 · 旧接口兼容"
        case .tripleDES: "64 位分组 · 16 / 24 字节密钥"
        case .aes: "128 位分组 · 16 / 24 / 32 字节密钥"
        case .rsa: "公钥加密 / 私钥解密 · PEM / XML 密钥"
        case .sm2: "国密非对称算法 · sm2p256v1 · ASN.1 DER 密文"
        case .sm3: "国密摘要算法 · 256 位摘要"
        case .sm4: "国密分组算法 · 16 字节密钥"
        }
    }
}

public enum TextFormat: String, CaseIterable, Codable, Identifiable, Sendable {
    case utf8 = "UTF-8", base64 = "Base64", hex = "Hex"
    public var id: String { rawValue }
    public func decode(_ text: String) throws -> Data {
        switch self {
        case .utf8: return Data(text.utf8)
        case .base64:
            let clean = text.filter { !$0.isWhitespace }
            guard clean.utf8.count % 4 == 0, let data = Data(base64Encoded: clean), data.base64EncodedString() == clean else {
                throw CryptoError.message("Base64 格式不正确，请使用标准 Base64（包含必要的 = 填充）。")
            }
            return data
        case .hex:
            var clean = text.filter { !$0.isWhitespace }
            if clean.hasPrefix("0x") || clean.hasPrefix("0X") { clean.removeFirst(2) }
            let bytes = Array(clean.utf8)
            guard bytes.count % 2 == 0 else { throw CryptoError.message("Hex 必须由偶数个十六进制字符组成。") }
            var result = Data(); result.reserveCapacity(bytes.count / 2)
            func digit(_ value: UInt8) -> UInt8? {
                switch value { case 48...57: value - 48; case 65...70: value - 55; case 97...102: value - 87; default: nil }
            }
            for i in stride(from: 0, to: bytes.count, by: 2) {
                guard let high = digit(bytes[i]), let low = digit(bytes[i+1]) else {
                    throw CryptoError.message("Hex 仅接受 0–9、a–f，可包含空格、换行及 0x 前缀。")
                }
                result.append(high * 16 + low)
            }
            return result
        }
    }
    public func encode(_ data: Data) throws -> String {
        switch self {
        case .utf8:
            guard let text = String(data: data, encoding: .utf8) else {
                throw CryptoError.message("结果不是有效的 UTF-8 文本，请将输出格式改为 Base64 或 Hex 后重新执行。")
            }
            return text
        case .base64: return data.base64EncodedString()
        case .hex: return data.map { String(format: "%02x", $0) }.joined()
        }
    }
}

public enum CryptoOperation: String, CaseIterable, Codable, Identifiable, Sendable {
    case encrypt = "加密", decrypt = "解密", digest = "摘要"
    public var id: String { rawValue }
}
public enum BlockMode: String, CaseIterable, Codable, Sendable { case cbc = "CBC", ecb = "ECB" }
public enum Padding: String, CaseIterable, Codable, Sendable { case pkcs7 = "PKCS7", none = "NoPadding" }
public enum RSAPadding: String, CaseIterable, Codable, Sendable { case oaep = "OAEP · SHA-256", pkcs1 = "PKCS#1 v1.5" }

public enum AsymmetricKeyFormat: String, Codable, Identifiable, Sendable {
    case pem = "PEM", hex = "Hex", xml = "XML"
    public var id: String { rawValue }
    public static func supported(for algorithm: Algorithm) -> [Self] {
        algorithm == .sm2 ? [.hex, .pem] : [.xml, .pem]
    }
}

public enum CryptoError: LocalizedError, Equatable {
    case message(String)
    public var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}

public struct CryptoRequest: Codable, Equatable, Sendable {
    public var algorithm: Algorithm = .aes
    public var operation: CryptoOperation = .encrypt
    public var input = ""
    public var inputFormat: TextFormat = .utf8
    public var outputFormat: TextFormat = .base64
    public var key = ""
    public var keyFormat: TextFormat = .hex
    public var iv = ""
    public var ivFormat: TextFormat = .hex
    public var publicKey = ""
    public var privateKey = ""
    // Optional preserves decoding of keys and history created by version 1.0.
    public var asymmetricKeyFormat: AsymmetricKeyFormat?
    public var resolvedKeyFormat: AsymmetricKeyFormat { asymmetricKeyFormat ?? .pem }
    public var mode: BlockMode = .cbc
    public var padding: Padding = .pkcs7
    public var rsaPadding: RSAPadding = .oaep
    public var savedKeyID: UUID?
    public init() {}
    public var withoutSecrets: CryptoRequest {
        var copy = self; copy.key = ""; copy.publicKey = ""; copy.privateKey = ""; return copy
    }
}

public struct CryptoResult: Sendable {
    public let text: String
    public let inputBytes: Int
    public let outputBytes: Int
    public let milliseconds: Double
}

public struct KeyRecord: Codable, Identifiable, Sendable {
    public var id = UUID()
    public var name: String
    public var algorithm: Algorithm
    public var key: String
    public var keyFormat: TextFormat
    public var publicKey: String
    public var privateKey: String
    public var asymmetricKeyFormat: AsymmetricKeyFormat?
    public var resolvedKeyFormat: AsymmetricKeyFormat { asymmetricKeyFormat ?? .pem }
    public var createdAt = Date()
    public init(name: String, request: CryptoRequest) {
        self.name = name; algorithm = request.algorithm; key = request.key; keyFormat = request.keyFormat
        publicKey = request.publicKey; privateKey = request.privateKey
        asymmetricKeyFormat = request.asymmetricKeyFormat
    }
    public func applying(to original: CryptoRequest) -> CryptoRequest {
        var request = original; request.algorithm = algorithm; request.key = key; request.keyFormat = keyFormat
        request.publicKey = publicKey; request.privateKey = privateKey
        request.asymmetricKeyFormat = asymmetricKeyFormat; request.savedKeyID = id; return request
    }
}

public struct HistoryRecord: Codable, Identifiable, Sendable {
    public var id = UUID()
    public let createdAt: Date
    public let request: CryptoRequest
    public let output: String
    public let inputBytes: Int
    public let outputBytes: Int
    public let milliseconds: Double
    public init(request: CryptoRequest, result: CryptoResult) {
        createdAt = Date(); self.request = request.withoutSecrets; output = result.text
        inputBytes = result.inputBytes; outputBytes = result.outputBytes; milliseconds = result.milliseconds
    }
}

public struct VaultDocument: Codable {
    public var version = 1
    public var keys: [KeyRecord] = []
    public var history: [HistoryRecord] = []
    public init() {}
}
