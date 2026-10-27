import SwiftUI
import AppKit
import CryptoCore

enum Route: Equatable { case workbench, keys, history }

@MainActor final class AppStore: ObservableObject {
    @Published var route: Route = .workbench
    @Published var request = CryptoRequest()
    @Published var result: CryptoResult?
    @Published var document = VaultDocument()
    @Published var busy = false
    @Published var rememberHistory = true
    @Published var error: String?
    @Published var notice: String?
    @Published var storageReady = false
    @Published var rsaBits = 2048
    let vault = LocalVault()

    init() { unlock() }
    func unlock() {
        do { document = try vault.load(); storageReady = true }
        catch { self.error = error.localizedDescription; storageReady = false }
    }
    func select(_ algorithm: Algorithm) {
        guard algorithm != request.algorithm else { route = .workbench; return }
        request = CryptoRequest(); request.algorithm = algorithm
        request.asymmetricKeyFormat = algorithm == .sm2 ? .hex : (algorithm == .rsa ? .xml : nil)
        request.operation = algorithm.isDigest ? .digest : .encrypt
        request.outputFormat = algorithm.isDigest ? .hex : .base64
        result = nil; notice = nil; route = .workbench
    }
    func setOperation(_ operation: CryptoOperation) {
        guard request.operation != operation else { return }
        request.operation = operation
        request.inputFormat = operation == .decrypt ? .base64 : .utf8
        request.outputFormat = operation == .decrypt ? .utf8 : .base64
        result = nil
    }
    func setKeyFormat(_ format: AsymmetricKeyFormat) {
        guard !busy, format != request.resolvedKeyFormat else { return }
        do {
            var converted = request
            if !request.publicKey.isEmpty {
                converted.publicKey = try AsymmetricKeyCodec.convert(request.publicKey, algorithm: request.algorithm,
                    isPrivate: false, from: request.resolvedKeyFormat, to: format)
            }
            if !request.privateKey.isEmpty {
                converted.privateKey = try AsymmetricKeyCodec.convert(request.privateKey, algorithm: request.algorithm,
                    isPrivate: true, from: request.resolvedKeyFormat, to: format)
            }
            converted.asymmetricKeyFormat = format; converted.savedKeyID = nil
            request = converted; result = nil; notice = "密钥格式已切换为 \(format.rawValue)。"
        } catch { self.error = error.localizedDescription }
    }
    func run() {
        guard !busy else { return }
        var candidate = request
        candidate.savedKeyID = document.keys.first(where: {
            $0.algorithm == request.algorithm && $0.key == request.key && $0.keyFormat == request.keyFormat &&
            $0.publicKey == request.publicKey && $0.privateKey == request.privateKey &&
            $0.resolvedKeyFormat == request.resolvedKeyFormat
        })?.id
        let snapshot = candidate
        busy = true; result = nil; notice = nil
        Task {
            do {
                let value = try await Task.detached(priority: .userInitiated) { try CryptoEngine.execute(snapshot) }.value
                result = value
                if rememberHistory && storageReady {
                    var updated = document
                    updated.history.insert(HistoryRecord(request: snapshot, result: value), at: 0)
                    updated.history = Array(updated.history.prefix(500))
                    var totalBytes = 0
                    updated.history = updated.history.filter {
                        totalBytes += $0.request.input.utf8.count + $0.output.utf8.count
                        return totalBytes <= 20 * 1_048_576
                    }
                    do { try persist(updated) }
                    catch { self.error = "运算已完成，但历史记录保存失败。\n" + error.localizedDescription }
                }
            } catch { self.error = error.localizedDescription }
            busy = false
        }
    }
    func generate() {
        guard !busy else { return }
        busy = true; notice = nil
        let algorithm = request.algorithm, bits = rsaBits
        let asymmetricFormat = request.resolvedKeyFormat
        let format: TextFormat = request.keyFormat == .utf8 ? .hex : request.keyFormat
        Task {
            do {
                if algorithm.isAsymmetric {
                    let pair = try await Task.detached(priority: .userInitiated) {
                        try CryptoEngine.generate(algorithm: algorithm, bits: bits, format: asymmetricFormat)
                    }.value
                    request.publicKey = pair.publicKey; request.privateKey = pair.privateKey
                } else {
                    request.key = try format.encode(CryptoEngine.random(bytes: algorithm.keyBytes))
                    request.keyFormat = format
                }
                request.savedKeyID = nil; result = nil
                notice = "新密钥已生成，点击“保存密钥”可存入本地密钥库。"
            } catch { self.error = error.localizedDescription }
            busy = false
        }
    }
    func randomIV() {
        do {
            if request.ivFormat == .utf8 { request.ivFormat = .hex }
            request.iv = try request.ivFormat.encode(CryptoEngine.random(bytes: request.algorithm.blockBytes)); result = nil
        }
        catch { self.error = error.localizedDescription }
    }
    func saveKey(name: String) -> Bool {
        guard storageReady else { error = "本地数据尚未解锁，请先重新解锁。"; return false }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 80 else { error = "密钥名称需要 1–80 个字符。"; return false }
        do {
            try CryptoEngine.validateKey(request)
            let record = KeyRecord(name: trimmed, request: request)
            var updated = document; updated.keys.insert(record, at: 0)
            try persist(updated); request.savedKeyID = record.id; notice = "密钥已保存到本地密钥库。"; return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func applyKey(_ record: KeyRecord) {
        if request.algorithm != record.algorithm { select(record.algorithm) }
        request = record.applying(to: request); result = nil; route = .workbench; notice = "已载入密钥：\(record.name)"
    }
    func deleteKey(_ id: UUID) {
        do {
            var updated = document; updated.keys.removeAll { $0.id == id }; try persist(updated)
            if request.savedKeyID == id { request.savedKeyID = nil }
        } catch { self.error = error.localizedDescription }
    }
    func deleteHistory(_ id: UUID? = nil) {
        do {
            var updated = document
            if let id { updated.history.removeAll { $0.id == id } } else { updated.history = [] }
            try persist(updated)
        } catch { self.error = error.localizedDescription }
    }
    func restore(_ record: HistoryRecord) {
        request = record.request
        if let id = record.request.savedKeyID, let key = document.keys.first(where: { $0.id == id }) {
            request = key.applying(to: request)
        } else { request.savedKeyID = nil }
        result = nil; route = .workbench
        notice = request.algorithm.isDigest ? "历史输入和参数已载入。" : "历史输入和参数已载入；请确认密钥后执行。"
    }
    func useOutput() {
        guard let result, !request.algorithm.isDigest else { return }
        request.input = result.text
        request.inputFormat = request.outputFormat
        request.operation = request.operation == .encrypt ? .decrypt : .encrypt
        request.outputFormat = request.operation == .decrypt ? .utf8 : .base64
        self.result = nil
    }
    func copy(_ value: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string); notice = "已复制到剪贴板。" }
    private func persist(_ updated: VaultDocument) throws { try vault.save(updated); document = updated }
}
