import Foundation
import CryptoCore

extension CryptoCoreTests {
    func testSM2HexKeyInterchange() throws {
        let pair = try CryptoEngine.generate(algorithm: .sm2, format: .hex)
        Check.equal(pair.publicKey.count, 130); Check.equal(pair.privateKey.count, 64)
        Check.equal(String(pair.publicKey.prefix(2)), "04")
        let pubPEM = try AsymmetricKeyCodec.convert(pair.publicKey, algorithm: .sm2, isPrivate: false, from: .hex, to: .pem)
        let privPEM = try AsymmetricKeyCodec.convert(pair.privateKey, algorithm: .sm2, isPrivate: true, from: .hex, to: .pem)
        Check.equal(try AsymmetricKeyCodec.convert(pubPEM, algorithm: .sm2, isPrivate: false, from: .pem, to: .hex), pair.publicKey)
        Check.equal(try AsymmetricKeyCodec.convert(privPEM, algorithm: .sm2, isPrivate: true, from: .pem, to: .hex), pair.privateKey)
        var request = CryptoRequest(); request.algorithm = .sm2; request.asymmetricKeyFormat = .hex
        request.publicKey = "0x" + pair.publicKey.dropFirst(2).uppercased(); request.privateKey = pair.privateKey
        request.input = "SM2 Hex 互通测试 🔐"
        Check.noThrow(try CryptoEngine.validateKey(request))
        let encrypted = try CryptoEngine.execute(request).text
        request.operation = .decrypt; request.input = encrypted; request.inputFormat = .base64; request.outputFormat = .utf8
        request.privateKey = privPEM; request.asymmetricKeyFormat = .pem
        Check.equal(try CryptoEngine.execute(request).text, "SM2 Hex 互通测试 🔐")
        request.operation = .encrypt; request.publicKey = pubPEM; request.input = "PEM to Hex"; request.inputFormat = .utf8; request.outputFormat = .base64
        request.input = try CryptoEngine.execute(request).text
        request.operation = .decrypt; request.privateKey = pair.privateKey; request.asymmetricKeyFormat = .hex
        request.inputFormat = .base64; request.outputFormat = .utf8
        Check.equal(try CryptoEngine.execute(request).text, "PEM to Hex")
        // Scalar 1 exercises fixed-width private-key encoding and public-point derivation.
        let one = String(repeating: "0", count: 63) + "1"
        let onePEM = try AsymmetricKeyCodec.toPEM(one, algorithm: .sm2, isPrivate: true, format: .hex)
        Check.equal(try AsymmetricKeyCodec.convert(onePEM, algorithm: .sm2, isPrivate: true, from: .pem, to: .hex), one)
    }

    func testRSAXMLKeyInterchange() throws {
        let pair = try CryptoEngine.generate(algorithm: .rsa, format: .xml)
        Check.equal(pair.publicKey.hasPrefix("<RSAKeyValue>"), true)
        Check.isFalse(pair.publicKey.contains("<D>"))
        for field in ["Modulus", "Exponent", "P", "Q", "DP", "DQ", "InverseQ", "D"] {
            Check.equal(pair.privateKey.contains("<\(field)>"), true)
        }
        let pubPEM = try AsymmetricKeyCodec.convert(pair.publicKey, algorithm: .rsa, isPrivate: false, from: .xml, to: .pem)
        let privPEM = try AsymmetricKeyCodec.convert(pair.privateKey, algorithm: .rsa, isPrivate: true, from: .xml, to: .pem)
        Check.equal(try AsymmetricKeyCodec.convert(pubPEM, algorithm: .rsa, isPrivate: false, from: .pem, to: .xml), pair.publicKey)
        Check.equal(try AsymmetricKeyCodec.convert(privPEM, algorithm: .rsa, isPrivate: true, from: .pem, to: .xml), pair.privateKey)
        for padding in RSAPadding.allCases {
            var request = CryptoRequest(); request.algorithm = .rsa; request.asymmetricKeyFormat = .xml; request.rsaPadding = padding
            request.publicKey = pair.publicKey; request.privateKey = pair.privateKey; request.input = "RSA XML 互通 🔐"
            Check.noThrow(try CryptoEngine.validateKey(request))
            let encrypted = try CryptoEngine.execute(request).text
            request.operation = .decrypt; request.input = encrypted; request.inputFormat = .base64; request.outputFormat = .utf8
            request.privateKey = privPEM; request.asymmetricKeyFormat = .pem
            Check.equal(try CryptoEngine.execute(request).text, "RSA XML 互通 🔐")
            request.operation = .encrypt; request.publicKey = pubPEM; request.input = "PEM to XML"; request.inputFormat = .utf8; request.outputFormat = .base64
            request.input = try CryptoEngine.execute(request).text
            request.operation = .decrypt; request.privateKey = pair.privateKey; request.asymmetricKeyFormat = .xml
            request.inputFormat = .base64; request.outputFormat = .utf8
            Check.equal(try CryptoEngine.execute(request).text, "PEM to XML")
        }
    }

    func testMalformedAsymmetricKeyFormats() throws {
        for key in [String(repeating: "0", count: 64), String(repeating: "f", count: 64), "01", "zz"] {
            Check.throwsError(try AsymmetricKeyCodec.toPEM(key, algorithm: .sm2, isPrivate: true, format: .hex))
        }
        for key in ["04" + String(repeating: "0", count: 128), "03" + String(repeating: "1", count: 128)] {
            Check.throwsError(try AsymmetricKeyCodec.toPEM(key, algorithm: .sm2, isPrivate: false, format: .hex))
        }
        for xml in [
            "<Other/>",
            "<RSAKeyValue><Modulus>###=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "<RSAKeyValue><Modulus>AQ==</Modulus><Modulus>AQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "<!DOCTYPE RSAKeyValue [<!ENTITY x SYSTEM 'file:///dev/null'>]><RSAKeyValue/>",
            "<RSAKeyValue><Modulus>AQ==</Modulus><Exponent>AQAB</Exponent><Unknown>AQ==</Unknown></RSAKeyValue>"
        ] { Check.throwsError(try AsymmetricKeyCodec.toPEM(xml, algorithm: .rsa, isPrivate: false, format: .xml)) }
        let pair = try CryptoEngine.generate(algorithm: .rsa, format: .xml)
        Check.throwsError(try AsymmetricKeyCodec.toPEM(pair.publicKey, algorithm: .rsa, isPrivate: true, format: .xml))
        let invalidD = pair.privateKey.replacingOccurrences(of: "<D>[^<]+</D>", with: "<D>AQ==</D>", options: .regularExpression)
        Check.throwsError(try AsymmetricKeyCodec.toPEM(invalidD, algorithm: .rsa, isPrivate: true, format: .xml))
        Check.throwsError(try CryptoEngine.generate(algorithm: .sm2, format: .xml))
        Check.throwsError(try CryptoEngine.generate(algorithm: .rsa, format: .hex))
    }

    func testKeyFormatPersistenceAndLegacyCompatibility() throws {
        for (algorithm, format) in [(Algorithm.sm2, AsymmetricKeyFormat.hex), (.rsa, .xml)] {
            let pair = try CryptoEngine.generate(algorithm: algorithm, format: format)
            var request = CryptoRequest(); request.algorithm = algorithm; request.asymmetricKeyFormat = format
            request.publicKey = pair.publicKey; request.privateKey = pair.privateKey; request.input = "format persistence"
            let key = KeyRecord(name: "format fixture", request: request)
            let encoded = try JSONEncoder().encode(key)
            let reloaded = try JSONDecoder().decode(KeyRecord.self, from: encoded)
            let restored = reloaded.applying(to: CryptoRequest())
            Check.equal(restored.resolvedKeyFormat, format)
            Check.noThrow(try CryptoEngine.validateKey(restored))
            let history = HistoryRecord(request: request, result: try CryptoEngine.execute(request))
            let historyCopy = try JSONDecoder().decode(HistoryRecord.self, from: JSONEncoder().encode(history))
            Check.equal(historyCopy.request.resolvedKeyFormat, format)
            Check.equal(historyCopy.request.publicKey, ""); Check.equal(historyCopy.request.privateKey, "")
        }
        var legacy = CryptoRequest(); legacy.algorithm = .rsa
        let pair = try CryptoEngine.generate(algorithm: .rsa)
        legacy.publicKey = pair.publicKey; legacy.privateKey = pair.privateKey
        var oldJSON = try JSONSerialization.jsonObject(with: JSONEncoder().encode(legacy)) as! [String: Any]
        oldJSON.removeValue(forKey: "asymmetricKeyFormat")
        let old = try JSONDecoder().decode(CryptoRequest.self, from: JSONSerialization.data(withJSONObject: oldJSON))
        Check.equal(old.resolvedKeyFormat, .pem); Check.noThrow(try CryptoEngine.validateKey(old))
        let oldKey = KeyRecord(name: "legacy fixture", request: legacy)
        var oldKeyJSON = try JSONSerialization.jsonObject(with: JSONEncoder().encode(oldKey)) as! [String: Any]
        oldKeyJSON.removeValue(forKey: "asymmetricKeyFormat")
        let decoded = try JSONDecoder().decode(KeyRecord.self, from: JSONSerialization.data(withJSONObject: oldKeyJSON))
        Check.equal(decoded.applying(to: CryptoRequest()).resolvedKeyFormat, .pem)
    }
}
