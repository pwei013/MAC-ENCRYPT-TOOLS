import Foundation
import CryptoKit
import CryptoCore

final class CryptoCoreTests {
    func testStrictFormatsAndUnicode() throws {
        let bytes = Data("摩快云 🔐\nhello".utf8)
        for format in TextFormat.allCases { Check.equal(try format.decode(format.encode(bytes)), bytes) }
        Check.equal(try TextFormat.hex.decode("0x00 fF\n12"), Data([0, 255, 18]))
        for text in ["0", "gg", "中文"] { Check.throwsError(try TextFormat.hex.decode(text)) }
        for text in ["a", "a===", "###=", "ab=="] { Check.throwsError(try TextFormat.base64.decode(text)) }
        Check.throwsError(try TextFormat.utf8.encode(Data([0xff])))
    }
    func testKnownDigestsIncludingEmpty() throws {
        let cases: [(Algorithm, String, String)] = [
            (.md5, "abc", "900150983cd24fb0d6963f7d28e17f72"),
            (.md5, "", "d41d8cd98f00b204e9800998ecf8427e"),
            (.sha256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (.sm3, "abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        ]
        for (algorithm, input, expected) in cases {
            var request = CryptoRequest(); request.algorithm = algorithm; request.operation = .digest
            request.input = input; request.outputFormat = .hex
            Check.equal(try CryptoEngine.execute(request).text, expected)
        }
    }
    func testStandardBlockVectors() throws {
        let vectors: [(Algorithm, String, String, String)] = [
            (.des, "133457799bbcdff1", "0123456789abcdef", "85e813540f0ab405"),
            (.sm4, "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "681edf34d206965e86b3e94f536e4246"),
            (.aes, "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a")
        ]
        for (algorithm, key, plain, cipher) in vectors {
            var request = CryptoRequest(); request.algorithm = algorithm; request.key = key
            request.mode = .ecb; request.padding = .none; request.inputFormat = .hex; request.outputFormat = .hex; request.input = plain
            Check.equal(try CryptoEngine.execute(request).text, cipher)
            request.operation = .decrypt; request.input = cipher
            Check.equal(try CryptoEngine.execute(request).text, plain)
        }
    }
    func testAllSymmetricModesKeyLengthsAndPaddings() throws {
        for algorithm in [Algorithm.des, .tripleDES, .aes, .sm4] {
            let sizes: [Int] = algorithm == .tripleDES ? [16,24] : (algorithm == .aes ? [16,24,32] : [algorithm.keyBytes])
            for size in sizes { for mode in BlockMode.allCases { for padding in Padding.allCases {
                var request = CryptoRequest(); request.algorithm = algorithm; request.mode = mode; request.padding = padding
                request.key = try TextFormat.hex.encode(CryptoEngine.random(bytes: size))
                request.iv = try TextFormat.hex.encode(CryptoEngine.random(bytes: algorithm.blockBytes))
                request.inputFormat = .hex; request.outputFormat = .base64
                let plain = padding == .none ? try CryptoEngine.random(bytes: algorithm.blockBytes * 3) : Data("摩快云 hello 🔐".utf8)
                request.input = try TextFormat.hex.encode(plain)
                let encrypted = try CryptoEngine.execute(request).text
                request.operation = .decrypt; request.inputFormat = .base64; request.outputFormat = .hex; request.input = encrypted
                Check.equal(try CryptoEngine.execute(request).text, try TextFormat.hex.encode(plain))
            } } }
        }
    }
    func testAsymmetricRoundTripsAndWrongKeys() throws {
        for algorithm in [Algorithm.rsa, .sm2] {
            let pair = try CryptoEngine.generate(algorithm: algorithm)
            let other = try CryptoEngine.generate(algorithm: algorithm)
            for padding in (algorithm == .rsa ? RSAPadding.allCases : [.oaep]) {
                var request = CryptoRequest(); request.algorithm = algorithm; request.rsaPadding = padding
                request.publicKey = pair.publicKey; request.privateKey = pair.privateKey
                request.input = "你好 CipherDesk 🔐"
                let encrypted = try CryptoEngine.execute(request).text
                request.operation = .decrypt; request.inputFormat = .base64; request.input = encrypted; request.outputFormat = .utf8
                Check.equal(try CryptoEngine.execute(request).text, "你好 CipherDesk 🔐")
                request.privateKey = other.privateKey
                Check.throwsError(try CryptoEngine.execute(request))
            }
        }
    }
    func testValidationRejectsWrongKeyIVAndSize() throws {
        var request = CryptoRequest(); request.key = "00"; request.input = "test"
        Check.throwsError(try CryptoEngine.execute(request))
        request.key = String(repeating: "00", count: 32); request.iv = "00"
        Check.throwsError(try CryptoEngine.execute(request))
        request.mode = .ecb; request.padding = .none
        Check.throwsError(try CryptoEngine.execute(request))
        request.input = String(repeating: "a", count: CryptoEngine.maximumInputBytes + 1)
        Check.throwsError(try CryptoEngine.execute(request))
        request.algorithm = .md5; request.operation = .decrypt; request.input = "x"
        Check.throwsError(try CryptoEngine.execute(request))
    }
    func testRSAInputBoundaries() throws {
        let pair = try CryptoEngine.generate(algorithm: .rsa)
        var request = CryptoRequest(); request.algorithm = .rsa; request.publicKey = pair.publicKey
        request.input = String(repeating: "a", count: 190)
        Check.noThrow(try CryptoEngine.execute(request))
        request.input += "a"; Check.throwsError(try CryptoEngine.execute(request))
        request.rsaPadding = .pkcs1; request.input = String(repeating: "a", count: 245)
        Check.noThrow(try CryptoEngine.execute(request))
        request.input += "a"; Check.throwsError(try CryptoEngine.execute(request))
    }
    func testHistoryNeverRetainsRawKeys() throws {
        var request = CryptoRequest(); request.key = "symmetric-secret"; request.privateKey = "private-secret"; request.publicKey = "public-secret"
        request.algorithm = .md5; request.operation = .digest; request.outputFormat = .hex; request.input = "demo"
        let record = HistoryRecord(request: request, result: try CryptoEngine.execute(request))
        let data = try JSONEncoder().encode(record)
        let text = String(decoding: data, as: UTF8.self)
        Check.isFalse(text.contains("symmetric-secret")); Check.isFalse(text.contains("private-secret")); Check.isFalse(text.contains("public-secret"))
    }
    func testSavedKeyValidationAndRestoration() throws {
        let pair = try CryptoEngine.generate(algorithm: .sm2)
        var request = CryptoRequest(); request.algorithm = .sm2
        request.publicKey = pair.publicKey; request.privateKey = pair.privateKey
        Check.noThrow(try CryptoEngine.validateKey(request))
        let saved = KeyRecord(name: "fixture", request: request)
        var input = CryptoRequest(); input.input = "preserved input"; input.inputFormat = .utf8
        let restored = saved.applying(to: input)
        Check.equal(restored.algorithm, .sm2); Check.equal(restored.savedKeyID, saved.id)
        Check.equal(restored.input, "preserved input")
        request.privateKey = try CryptoEngine.generate(algorithm: .sm2).privateKey
        Check.throwsError(try CryptoEngine.validateKey(request))
        request.algorithm = .rsa
        Check.throwsError(try CryptoEngine.validateKey(request))
    }
    func testEmptyPlaintextAndInvalidBlockCiphertext() throws {
        var request = CryptoRequest(); request.algorithm = .aes
        request.key = String(repeating: "01", count: 32); request.iv = String(repeating: "00", count: 16)
        let encrypted = try CryptoEngine.execute(request)
        Check.equal(encrypted.outputBytes, 16)
        request.operation = .decrypt; request.inputFormat = .base64; request.outputFormat = .utf8; request.input = encrypted.text
        Check.equal(try CryptoEngine.execute(request).text, "")
        request.input = "AA=="
        Check.throwsError(try CryptoEngine.execute(request))
    }
    func testEncryptedPersistenceAndTamperDetection() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cipherdesk-test-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = TestKeyProvider(key: SymmetricKey(size: .bits256))
        let vault = LocalVault(directory: directory, keyProvider: provider)
        var document = try vault.load()
        var request = CryptoRequest(); request.key = "test-secret-never-in-plaintext"
        document.keys.append(KeyRecord(name: "fixture", request: request))
        var historyRequest = CryptoRequest(); historyRequest.algorithm = .md5; historyRequest.operation = .digest
        historyRequest.input = "history persistence fixture"; historyRequest.outputFormat = .hex
        document.history.append(HistoryRecord(request: historyRequest, result: try CryptoEngine.execute(historyRequest)))
        try vault.save(document)
        let bytes = try Data(contentsOf: vault.fileURL)
        Check.isNil(bytes.range(of: Data(request.key.utf8)))
        let reloaded = try LocalVault(directory: directory, keyProvider: provider).load()
        Check.equal(reloaded.keys.first?.key, request.key)
        Check.equal(reloaded.history.first?.request.input, historyRequest.input)
        Check.equal(reloaded.history.first?.output, document.history.first?.output)
        let permissions = try FileManager.default.attributesOfItem(atPath: vault.fileURL.path)[.posixPermissions] as? NSNumber
        Check.equal(permissions?.intValue, 0o600)
        var cleared = reloaded; cleared.keys = []; cleared.history = []; try vault.save(cleared)
        let empty = try LocalVault(directory: directory, keyProvider: provider).load()
        Check.equal(empty.keys.count, 0); Check.equal(empty.history.count, 0)
        var damaged = bytes; damaged[damaged.count / 2] ^= 1; try damaged.write(to: vault.fileURL)
        Check.throwsError(try LocalVault(directory: directory, keyProvider: provider).load())
        Check.equal(try Data(contentsOf: vault.fileURL), damaged)
    }
}

private struct TestKeyProvider: VaultKeyProvider {
    let key: SymmetricKey
    func loadOrCreate(allowCreate: Bool) throws -> SymmetricKey { key }
}
