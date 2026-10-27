import Foundation
import Security
import CryptoKit
import Darwin

public protocol VaultKeyProvider { func loadOrCreate(allowCreate: Bool) throws -> SymmetricKey }

public struct KeychainKeyProvider: VaultKeyProvider {
    private let service = "cn.mky.CipherDesk.local-vault"
    public init() {}
    public func loadOrCreate(allowCreate: Bool) throws -> SymmetricKey {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: "master-key-v1"]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query.merging([kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]) { _, new in new } as CFDictionary, &result)
        if status == errSecSuccess, let bytes = result as? Data, bytes.count == 32 { return SymmetricKey(data: bytes) }
        guard status == errSecItemNotFound, allowCreate else {
            throw CryptoError.message("无法读取本地数据的钥匙串密钥（状态码 \(status)）。请确认已解锁登录钥匙串；已有数据不会被覆盖。")
        }
        let bytes = try CryptoEngine.random(bytes: 32)
        let add = query.merging([kSecValueData as String: bytes,
                                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]) { _, new in new }
        let saved = SecItemAdd(add as CFDictionary, nil)
        if saved == errSecDuplicateItem { return try loadOrCreate(allowCreate: false) }
        guard saved == errSecSuccess else { throw CryptoError.message("保存钥匙串密钥失败（状态码 \(saved)）。") }
        return SymmetricKey(data: bytes)
    }
}

public final class LocalVault {
    public let directory: URL
    public var fileURL: URL { directory.appendingPathComponent("vault.enc") }
    private let keyProvider: any VaultKeyProvider
    private var encryptionKey: SymmetricKey?
    private let authenticatedData = Data("CipherDesk.vault.v1".utf8)
    public init(directory: URL? = nil, keyProvider: any VaultKeyProvider = KeychainKeyProvider()) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("CipherDesk", isDirectory: true)
        self.keyProvider = keyProvider
    }
    public func load() throws -> VaultDocument {
        let exists = FileManager.default.fileExists(atPath: fileURL.path)
        encryptionKey = try keyProvider.loadOrCreate(allowCreate: !exists)
        guard exists else { return VaultDocument() }
        do {
            let encrypted = try Data(contentsOf: fileURL)
            let box = try AES.GCM.SealedBox(combined: encrypted)
            let decoded = try AES.GCM.open(box, using: encryptionKey!, authenticating: authenticatedData)
            let document = try JSONDecoder().decode(VaultDocument.self, from: decoded)
            guard document.version == 1 else { throw CryptoError.message("本地数据版本暂不支持，文件已保留。") }
            return document
        } catch let error as CryptoError { throw error }
        catch { throw CryptoError.message("本地数据读取或完整性验证失败，文件已保留。请勿删除钥匙串中的 CipherDesk 密钥。") }
    }
    public func save(_ document: VaultDocument) throws {
        guard let encryptionKey else { throw CryptoError.message("本地数据尚未解锁，已停止保存。") }
        do {
            let fm = FileManager.default
            try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            guard chmod(directory.path, 0o700) == 0 else { throw CryptoError.message("无法设置本地数据目录权限。") }
            let plain = try JSONEncoder().encode(document)
            let encrypted = try AES.GCM.seal(plain, using: encryptionKey, authenticating: authenticatedData).combined!
            try encrypted.write(to: fileURL, options: [.atomic])
            guard chmod(fileURL.path, 0o600) == 0 else { throw CryptoError.message("本地数据已写入，但文件权限设置失败。") }
        } catch let error as CryptoError { throw error }
        catch { throw CryptoError.message("本地数据保存失败，请检查磁盘空间和目录权限。") }
    }
}
