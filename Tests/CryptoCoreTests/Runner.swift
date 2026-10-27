import Foundation

// A small deterministic runner keeps core verification available with Apple's
// Command Line Tools, which do not ship the XCTest framework.
enum Check {
    static var failures = 0
    static func fail(_ message: String, file: StaticString, line: UInt) {
        failures += 1
        print("  FAIL: \(message) [\(URL(fileURLWithPath: String(describing: file)).lastPathComponent):\(line)]")
    }
    static func equal<T: Equatable>(_ first: @autoclosure () throws -> T, _ second: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
        do { if try first() != second() { fail("values differ", file: file, line: line) } }
        catch { fail("unexpected error", file: file, line: line) }
    }
    static func throwsError<T>(_ expression: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
        do { _ = try expression(); fail("expected an error", file: file, line: line) } catch {}
    }
    static func noThrow<T>(_ expression: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
        do { _ = try expression() } catch { fail("unexpected error", file: file, line: line) }
    }
    static func isFalse(_ value: @autoclosure () -> Bool, file: StaticString = #filePath, line: UInt = #line) {
        if value() { fail("expected false", file: file, line: line) }
    }
    static func isNil<T>(_ value: @autoclosure () -> T?, file: StaticString = #filePath, line: UInt = #line) {
        if value() != nil { fail("expected nil", file: file, line: line) }
    }
}

@main enum SelfTestRunner {
    static func main() {
        let suite = CryptoCoreTests()
        let tests: [(String, () throws -> Void)] = [
            ("StrictFormatsAndUnicode", suite.testStrictFormatsAndUnicode),
            ("KnownDigestsIncludingEmpty", suite.testKnownDigestsIncludingEmpty),
            ("StandardBlockVectors", suite.testStandardBlockVectors),
            ("AllSymmetricModesKeyLengthsAndPaddings", suite.testAllSymmetricModesKeyLengthsAndPaddings),
            ("AsymmetricRoundTripsAndWrongKeys", suite.testAsymmetricRoundTripsAndWrongKeys),
            ("ValidationRejectsWrongKeyIVAndSize", suite.testValidationRejectsWrongKeyIVAndSize),
            ("RSAInputBoundaries", suite.testRSAInputBoundaries),
            ("HistoryNeverRetainsRawKeys", suite.testHistoryNeverRetainsRawKeys),
            ("SavedKeyValidationAndRestoration", suite.testSavedKeyValidationAndRestoration),
            ("EmptyPlaintextAndInvalidBlockCiphertext", suite.testEmptyPlaintextAndInvalidBlockCiphertext),
            ("EncryptedPersistenceAndTamperDetection", suite.testEncryptedPersistenceAndTamperDetection),
            ("SM2HexKeyInterchange", suite.testSM2HexKeyInterchange),
            ("RSAXMLKeyInterchange", suite.testRSAXMLKeyInterchange),
            ("MalformedAsymmetricKeyFormats", suite.testMalformedAsymmetricKeyFormats),
            ("KeyFormatPersistenceAndLegacyCompatibility", suite.testKeyFormatPersistenceAndLegacyCompatibility)
        ]
        for (name, test) in tests {
            let before = Check.failures
            do { try test() } catch { Check.fail("test threw an error", file: #filePath, line: #line) }
            print("\(Check.failures == before ? "PASS" : "FAIL") \(name)")
        }
        print("\(tests.count) test groups, \(Check.failures) failures")
        if Check.failures > 0 { exit(1) }
    }
}
