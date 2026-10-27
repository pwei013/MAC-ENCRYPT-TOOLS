import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif
import CryptoBridge

public enum AsymmetricKeyCodec {
    private static let rsaFields = ["Modulus", "Exponent", "P", "Q", "DP", "DQ", "InverseQ", "D"]

    public static func convert(_ value: String, algorithm: Algorithm, isPrivate: Bool,
                               from: AsymmetricKeyFormat, to: AsymmetricKeyFormat) throws -> String {
        let pem = try toPEM(value, algorithm: algorithm, isPrivate: isPrivate, format: from)
        guard AsymmetricKeyFormat.supported(for: algorithm).contains(to) else { throw invalidFormat() }
        switch to {
        case .pem: return pem
        case .hex:
            let data = try readBytes({ cd_sm2_export(pem, isPrivate ? 1 : 0, &$0, &$1) })
            return try TextFormat.hex.encode(data)
        case .xml:
            let fields = isPrivate ? rsaFields : Array(rsaFields.prefix(2))
            let lines = try fields.enumerated().map { index, name in
                let data = try readBytes({ cd_rsa_component(pem, isPrivate ? 1 : 0, Int32(index), &$0, &$1) })
                return "  <\(name)>\(data.base64EncodedString())</\(name)>"
            }
            return "<RSAKeyValue>\n" + lines.joined(separator: "\n") + "\n</RSAKeyValue>"
        }
    }

    public static func toPEM(_ value: String, algorithm: Algorithm, isPrivate: Bool,
                             format: AsymmetricKeyFormat) throws -> String {
        try CryptoEngine.prepare()
        guard algorithm.isAsymmetric, AsymmetricKeyFormat.supported(for: algorithm).contains(format) else { throw invalidFormat() }
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw CryptoError.message("请提供 \(format.rawValue) \(isPrivate ? "私钥" : "公钥")。")
        }
        guard value.utf8.count <= 65_536, !value.utf8.contains(0) else { throw invalidKey(format) }
        let pem: String
        switch format {
        case .pem: pem = value
        case .hex:
            var data = try TextFormat.hex.decode(value)
            if isPrivate {
                guard data.count == 32 else { throw CryptoError.message("SM2 私钥需要 64 个十六进制字符（32 字节）。") }
            } else {
                if data.count == 64 { data.insert(4, at: 0) }
                guard data.count == 65, data.first == 4 else {
                    throw CryptoError.message("SM2 公钥需要 130 个十六进制字符（04 + X + Y），也接受不带 04 前缀的 128 个字符。")
                }
            }
            var pointer: UnsafeMutablePointer<CChar>?, count = 0
            let ok = data.withUnsafeBytes { raw in
                cd_sm2_import(raw.bindMemory(to: UInt8.self).baseAddress, data.count, isPrivate ? 1 : 0, &pointer, &count)
            }
            defer { if let pointer { cd_release(pointer, count + 1) } }
            guard ok == 1, let pointer else { throw invalidKey(format) }
            pem = String(cString: pointer)
        case .xml:
            let fields = try parseXML(value)
            if isPrivate {
                guard rsaFields.allSatisfy({ fields[$0] != nil }) else {
                    throw CryptoError.message("RSA XML 私钥需要 Modulus、Exponent、P、Q、DP、DQ、InverseQ 和 D 字段。")
                }
                // PKCS#1 RSAPrivateKey: version, n, e, d, p, q, dp, dq, qi.
                let order = ["Modulus", "Exponent", "D", "P", "Q", "DP", "DQ", "InverseQ"]
                let content = derInteger(Data([0])) + order.reduce(into: Data()) { $0.append(derInteger(fields[$1]!)) }
                pem = wrapPEM(der(0x30, content), label: "RSA PRIVATE KEY")
            } else {
                guard let n = fields["Modulus"], let e = fields["Exponent"] else { throw invalidKey(format) }
                let rsa = der(0x30, derInteger(n) + derInteger(e))
                // rsaEncryption algorithm identifier followed by the public-key BIT STRING.
                let identifier = Data([0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00])
                pem = wrapPEM(der(0x30, identifier + der(0x03, Data([0]) + rsa)), label: "PUBLIC KEY")
            }
        }
        guard cd_validate_key(algorithm.rawValue, pem, isPrivate ? 1 : 0) == 1 else { throw invalidKey(format) }
        return pem
    }

    private static func readBytes(_ action: (inout UnsafeMutablePointer<UInt8>?, inout Int) -> Int32) throws -> Data {
        var pointer: UnsafeMutablePointer<UInt8>?, length = 0
        let ok = action(&pointer, &length)
        defer { if let pointer { cd_release(pointer, length) } }
        guard ok == 1, let pointer else { throw CryptoError.message("密钥格式转换失败，请检查密钥类型和完整性。") }
        return Data(bytes: pointer, count: length)
    }
    private static func invalidFormat() -> CryptoError { .message("该算法不支持此密钥格式。SM2 支持 Hex / PEM，RSA 支持 XML / PEM。") }
    private static func invalidKey(_ format: AsymmetricKeyFormat) -> CryptoError {
        .message("\(format.rawValue) 密钥格式、类型或参数不正确。PEM 私钥不支持口令保护。")
    }
    private static func der(_ tag: UInt8, _ data: Data) -> Data {
        var result = Data([tag])
        if data.count < 128 { result.append(UInt8(data.count)) }
        else {
            var length = data.count, bytes: [UInt8] = []
            while length > 0 { bytes.insert(UInt8(length & 255), at: 0); length >>= 8 }
            result.append(0x80 | UInt8(bytes.count)); result.append(contentsOf: bytes)
        }
        result.append(data); return result
    }
    private static func derInteger(_ value: Data) -> Data {
        var bytes = Data(value.drop(while: { $0 == 0 }))
        if bytes.isEmpty { bytes = Data([0]) }
        else if bytes[0] >= 128 { bytes.insert(0, at: 0) }
        return der(0x02, bytes)
    }
    private static func wrapPEM(_ data: Data, label: String) -> String {
        let text = data.base64EncodedString()
        let lines = stride(from: 0, to: text.count, by: 64).map { start -> String in
            let lower = text.index(text.startIndex, offsetBy: start)
            let upper = text.index(lower, offsetBy: min(64, text.count - start))
            return String(text[lower..<upper])
        }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }
    private static func parseXML(_ value: String) throws -> [String: Data] {
        let upper = value.uppercased()
        guard !upper.contains("<!DOCTYPE"), !upper.contains("<!ENTITY") else { throw invalidKey(.xml) }
        let delegate = RSAKeyXMLParser(allowedFields: Set(rsaFields))
        let parser = XMLParser(data: Data(value.utf8))
        parser.shouldResolveExternalEntities = false
        parser.externalEntityResolvingPolicy = .never
        parser.delegate = delegate
        guard parser.parse(), delegate.valid, delegate.closed, delegate.path.isEmpty else { throw invalidKey(.xml) }
        var decoded: [String: Data] = [:]
        for (name, value) in delegate.fields {
            let data = try TextFormat.base64.decode(value)
            guard !data.isEmpty, data.count <= 8192, data.contains(where: { $0 != 0 }) else { throw invalidKey(.xml) }
            decoded[name] = data
        }
        guard decoded["Modulus"] != nil, decoded["Exponent"] != nil else { throw invalidKey(.xml) }
        return decoded
    }
}

private final class RSAKeyXMLParser: NSObject, XMLParserDelegate {
    let allowedFields: Set<String>
    var fields: [String: String] = [:]
    var path: [String] = []
    var valid = true, closed = false
    private var value = ""
    init(allowedFields: Set<String>) { self.allowedFields = allowedFields }
    private func reject(_ parser: XMLParser) { valid = false; parser.abortParsing() }
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) {
        guard attributes.isEmpty, !closed else { reject(parser); return }
        if path.isEmpty {
            guard name == "RSAKeyValue" else { reject(parser); return }
        } else {
            guard path.count == 1, allowedFields.contains(name), fields[name] == nil else { reject(parser); return }
            value = ""
        }
        path.append(name)
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if path.count == 2 { value += string }
        else if !string.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { reject(parser) }
    }
    func parser(_ parser: XMLParser, foundCDATA data: Data) {
        guard let text = String(data: data, encoding: .utf8) else { reject(parser); return }
        self.parser(parser, foundCharacters: text)
    }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        guard path.last == name else { reject(parser); return }
        if path.count == 2 { fields[name] = value; value = "" }
        else { closed = true }
        path.removeLast()
    }
}
