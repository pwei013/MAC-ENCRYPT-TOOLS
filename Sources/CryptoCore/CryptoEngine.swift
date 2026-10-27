import Foundation
import Security
import CryptoBridge

public enum CryptoEngine {
    private static let initialized: Bool = cd_initialize() == 1
    public static var version: String { String(cString: cd_version()) }
    public static let maximumInputBytes = 1_048_576

    static func prepare() throws {
        guard initialized else { throw CryptoError.message("加密引擎初始化失败。") }
    }
    public static func random(bytes: Int) throws -> Data {
        guard bytes > 0 && bytes <= 4096 else { throw CryptoError.message("随机数据长度不合法。") }
        var data = Data(count: bytes)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }
        guard status == errSecSuccess else { throw CryptoError.message("系统安全随机数生成失败。") }
        return data
    }
    private static func takeOutput(_ perform: (inout UnsafeMutablePointer<UInt8>?, inout Int) -> Int32, error: String) throws -> Data {
        var pointer: UnsafeMutablePointer<UInt8>?
        var size = 0
        let status = perform(&pointer, &size)
        defer { if let pointer { cd_release(pointer, size) } }
        guard status == 1, let pointer else { throw CryptoError.message(error) }
        return Data(bytes: pointer, count: size)
    }
    public static func validateKey(_ request: CryptoRequest) throws {
        try prepare()
        if request.algorithm.isAsymmetric {
            guard !request.publicKey.isEmpty || !request.privateKey.isEmpty else { throw CryptoError.message("请先生成或粘贴密钥。") }
            let pub = request.publicKey.isEmpty ? nil : try AsymmetricKeyCodec.toPEM(request.publicKey, algorithm: request.algorithm, isPrivate: false, format: request.resolvedKeyFormat)
            let priv = request.privateKey.isEmpty ? nil : try AsymmetricKeyCodec.toPEM(request.privateKey, algorithm: request.algorithm, isPrivate: true, format: request.resolvedKeyFormat)
            if let pub, let priv {
                guard cd_validate_pair(pub, priv) == 1 else { throw CryptoError.message("公钥和私钥不属于同一密钥对，请检查后再保存。") }
            }
        } else if request.algorithm.isSymmetric {
            _ = try validatedSymmetricKey(request)
        }
    }
    private static func validatedSymmetricKey(_ request: CryptoRequest) throws -> Data {
        let key = try request.keyFormat.decode(request.key)
        let allowed: [Int] = switch request.algorithm { case .des: [8]; case .tripleDES: [16, 24]; case .aes: [16, 24, 32]; default: [16] }
        guard allowed.contains(key.count) else {
            throw CryptoError.message("\(request.algorithm.rawValue) 密钥需要 \(allowed.map(String.init).joined(separator: " / ")) 字节，当前为 \(key.count) 字节。")
        }
        return key
    }
    public static func generate(algorithm: Algorithm, bits: Int = 2048, format: AsymmetricKeyFormat = .pem) throws -> (publicKey: String, privateKey: String) {
        try prepare()
        guard algorithm.isAsymmetric, algorithm != .rsa || [2048,3072,4096].contains(bits) else { throw CryptoError.message("密钥生成参数不正确。") }
        guard AsymmetricKeyFormat.supported(for: algorithm).contains(format) else { throw CryptoError.message("该算法不支持所选密钥格式。") }
        var pub: UnsafeMutablePointer<CChar>?, priv: UnsafeMutablePointer<CChar>?
        var pubSize = 0, privSize = 0
        let ok = cd_generate(algorithm.rawValue, Int32(bits), &pub, &pubSize, &priv, &privSize)
        defer { if let pub { cd_release(pub, pubSize + 1) }; if let priv { cd_release(priv, privSize + 1) } }
        guard ok == 1, let pub, let priv else { throw CryptoError.message("密钥对生成失败，请重试。") }
        return (try AsymmetricKeyCodec.convert(String(cString: pub), algorithm: algorithm, isPrivate: false, from: .pem, to: format),
                try AsymmetricKeyCodec.convert(String(cString: priv), algorithm: algorithm, isPrivate: true, from: .pem, to: format))
    }
    public static func execute(_ request: CryptoRequest) throws -> CryptoResult {
        try prepare()
        let start = Date()
        guard request.input.utf8.count <= maximumInputBytes * 3 else { throw CryptoError.message("单次输入最多支持 1 MiB 原始数据。") }
        let input = try request.inputFormat.decode(request.input)
        guard input.count <= maximumInputBytes else { throw CryptoError.message("单次输入最多支持 1 MiB 原始数据。") }
        guard request.algorithm.isDigest ? request.operation == .digest : request.operation != .digest else { throw CryptoError.message("当前算法不支持该操作。") }
        let output: Data
        if request.algorithm.isDigest {
            let name = request.algorithm == .sha256 ? "SHA256" : request.algorithm.rawValue
            output = try input.withUnsafeBytes { bytes in
                try takeOutput({ cd_digest(name, bytes.bindMemory(to: UInt8.self).baseAddress, input.count, &$0, &$1) }, error: "摘要计算失败。")
            }
        } else if request.algorithm.isAsymmetric {
            let value = request.operation == .encrypt ? request.publicKey : request.privateKey
            let pem = try AsymmetricKeyCodec.toPEM(value, algorithm: request.algorithm,
                isPrivate: request.operation == .decrypt, format: request.resolvedKeyFormat)
            output = try input.withUnsafeBytes { bytes in
                try takeOutput({ cd_asymmetric(request.algorithm.rawValue, request.operation == .encrypt ? 1 : 0,
                    request.rsaPadding == .oaep ? 1 : 0, pem, bytes.bindMemory(to: UInt8.self).baseAddress,
                    input.count, &$0, &$1) }, error: request.algorithm == .rsa
                    ? "RSA 处理失败。请检查密钥、填充和输入长度；2048 位密钥单次最多加密 190 字节（OAEP）或 245 字节（PKCS#1）。"
                    : "SM2 处理失败。请检查密钥和密文；当前使用 ASN.1 DER 密文格式。")
            }
        } else {
            let key = try validatedSymmetricKey(request)
            let iv = request.mode == .cbc ? try request.ivFormat.decode(request.iv) : Data()
            guard request.mode != .cbc || iv.count == request.algorithm.blockBytes else {
                throw CryptoError.message("CBC 模式的 IV 需要 \(request.algorithm.blockBytes) 字节，当前为 \(iv.count) 字节。")
            }
            if request.padding == .none || request.operation == .decrypt {
                guard input.count % request.algorithm.blockBytes == 0 else { throw CryptoError.message("当前输入长度必须是 \(request.algorithm.blockBytes) 字节的整数倍。") }
            }
            let prefix: String = switch request.algorithm {
            case .des: "DES"
            case .tripleDES: key.count == 16 ? "DES-EDE" : "DES-EDE3"
            case .aes: "AES-\(key.count * 8)"
            default: "SM4"
            }
            // OpenSSL's two/three-key DES ECB names omit the mode suffix.
            let name = request.mode == .ecb && request.algorithm == .tripleDES ? prefix : "\(prefix)-\(request.mode.rawValue)"
            output = try key.withUnsafeBytes { keyBytes in try iv.withUnsafeBytes { ivBytes in try input.withUnsafeBytes { bytes in
                try takeOutput({ cd_cipher(name, request.operation == .encrypt ? 1 : 0, request.padding == .pkcs7 ? 1 : 0,
                    keyBytes.bindMemory(to: UInt8.self).baseAddress, key.count,
                    ivBytes.bindMemory(to: UInt8.self).baseAddress, iv.count,
                    bytes.bindMemory(to: UInt8.self).baseAddress, input.count, &$0, &$1) },
                    error: "处理失败，请检查密钥、IV、分组模式、填充方式和密文。")
            } } }
        }
        return CryptoResult(text: try request.outputFormat.encode(output), inputBytes: input.count,
                            outputBytes: output.count, milliseconds: Date().timeIntervalSince(start) * 1000)
    }
}
