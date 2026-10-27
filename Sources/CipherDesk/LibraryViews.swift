import SwiftUI
import CryptoCore

struct KeysView: View {
    @EnvironmentObject var store: AppStore
    @ViewState private var search = ""
    @ViewState private var selectedID: UUID?
    @ViewState private var deleteID: UUID?
    @ViewState private var revealed = false
    private var filtered: [KeyRecord] { store.document.keys.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.algorithm.rawValue.localizedCaseInsensitiveContains(search) } }
    private var selected: KeyRecord? { filtered.first { $0.id == selectedID } ?? filtered.first }
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            PageHeading(eyebrow: "KEY LIBRARY", title: "本地密钥库", subtitle: "保存常用密钥，随时载入工作台使用。")
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(Theme.muted)
                TextField("搜索名称或算法", text: $search).textFieldStyle(.plain)
                Spacer(); Text("\(store.document.keys.count) 个密钥").font(.system(size: 11)).foregroundStyle(Theme.muted)
            }.padding(12).background(.white, in: RoundedRectangle(cornerRadius: 9))
            if let key = selected {
                HStack(alignment: .top, spacing: 18) {
                    ScrollView {
                        VStack(spacing: 8) { ForEach(filtered) { item in
                            Button { selectedID = item.id; revealed = false } label: {
                                VStack(alignment: .leading, spacing: 9) {
                                    HStack { Text(item.algorithm.rawValue).font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(Theme.blue); Spacer(); Image(systemName: "key.horizontal").foregroundStyle(Theme.muted) }
                                    Text(item.name).font(.system(size: 13, weight: .semibold)).lineLimit(2)
                                    Text(item.createdAt.formatted(date: .numeric, time: .shortened)).font(.system(size: 10)).foregroundStyle(Theme.muted)
                                }.padding(15).frame(maxWidth: .infinity, alignment: .leading)
                                    .background(.white, in: RoundedRectangle(cornerRadius: 10))
                                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(item.id == key.id ? Theme.blue.opacity(0.65) : Theme.line))
                            }.buttonStyle(.plain)
                        } }
                    }.frame(width: 225)
                    ScrollView {
                        Panel {
                            VStack(alignment: .leading, spacing: 18) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text(key.name).font(.system(size: 20, weight: .bold))
                                        Text("\(key.algorithm.rawValue) · \(key.algorithm.isAsymmetric ? key.resolvedKeyFormat.rawValue : key.algorithm.category)").font(.system(size: 11)).foregroundStyle(Theme.muted)
                                    }; Spacer()
                                    Button { store.applyKey(key) } label: { Label("使用此密钥", systemImage: "arrow.up.right") }.buttonStyle(.borderedProminent)
                                }
                                Divider()
                                if key.algorithm.isAsymmetric {
                                    if !key.publicKey.isEmpty { copyBlock("公钥", value: key.publicKey, hidden: false) }
                                    if !key.privateKey.isEmpty { copyBlock("私钥", value: key.privateKey, hidden: !revealed) }
                                } else { copyBlock("密钥 · \(key.keyFormat.rawValue)", value: key.key, hidden: !revealed) }
                                HStack {
                                    Button { revealed.toggle() } label: { Label(revealed ? "隐藏密钥" : "显示密钥", systemImage: revealed ? "eye.slash" : "eye") }
                                    Spacer(); Button("删除密钥", role: .destructive) { deleteID = key.id }
                                }.font(.system(size: 11))
                                Label("已加密保存在当前 Mac，主密钥由系统钥匙串管理。", systemImage: "lock.shield").font(.system(size: 10)).foregroundStyle(Theme.muted)
                            }
                        }
                    }
                }
            } else {
                EmptyState(icon: "key.horizontal", title: search.isEmpty ? "还没有保存的密钥" : "没有匹配的密钥", message: "在工作台生成或输入密钥后，点击“保存密钥”。")
                if search.isEmpty { Button("前往工作台") { store.route = .workbench }.buttonStyle(.borderedProminent).frame(maxWidth: .infinity) }
            }
            Spacer(minLength: 0)
        }.padding(30).padding(.top, 13)
        .alert("删除此密钥？", isPresented: Binding(get: { deleteID != nil }, set: { if !$0 { deleteID = nil } })) {
            Button("取消", role: .cancel) { deleteID = nil }
            Button("删除", role: .destructive) { if let deleteID { store.deleteKey(deleteID) }; deleteID = nil; revealed = false }
        } message: { Text("密钥将从本地密钥库删除，无法撤销。相关历史仍保留，但可能需要重新提供密钥才能运算。") }
    }
    private func copyBlock(_ title: String, value: String, hidden: Bool) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack { FieldLabel(text: title); Spacer(); Button { store.copy(value) } label: { Label("复制", systemImage: "doc.on.doc") }.font(.system(size: 10)) }
            if hidden {
                Text("••••••••••••••••••••••••").font(.system(size: 14, design: .monospaced)).foregroundStyle(Theme.muted).padding(14).frame(maxWidth: .infinity, alignment: .leading).background(Theme.background, in: RoundedRectangle(cornerRadius: 8))
            } else { CodeEditor(text: .constant(value), readOnly: true, height: value.contains("BEGIN") || value.contains("RSAKeyValue") ? 180 : 75) }
        }
    }
}

struct HistoryView: View {
    @EnvironmentObject var store: AppStore
    @ViewState private var search = ""
    @ViewState private var algorithmFilter = "全部算法"
    @ViewState private var selectedID: UUID?
    @ViewState private var clearAll = false
    @ViewState private var deleteID: UUID?
    private var filtered: [HistoryRecord] { store.document.history.filter {
        (algorithmFilter == "全部算法" || $0.request.algorithm.rawValue == algorithmFilter) &&
        (search.isEmpty || $0.request.input.localizedCaseInsensitiveContains(search) || $0.output.localizedCaseInsensitiveContains(search))
    } }
    private var selected: HistoryRecord? { filtered.first { $0.id == selectedID } ?? filtered.first }
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            PageHeading(eyebrow: "LOCAL HISTORY", title: "历史记录", subtitle: "查找以往的输入、结果和参数，载入后再次处理。")
            HStack(spacing: 12) {
                Image(systemName: "magnifyingglass").foregroundStyle(Theme.muted)
                TextField("搜索输入或结果", text: $search).textFieldStyle(.plain)
                Picker("算法筛选", selection: $algorithmFilter) { Text("全部算法").tag("全部算法"); ForEach(Algorithm.allCases) { Text($0.rawValue).tag($0.rawValue) } }.labelsHidden().frame(width: 130)
                Button("清空历史", role: .destructive) { clearAll = true }.disabled(store.document.history.isEmpty)
            }.padding(12).background(.white, in: RoundedRectangle(cornerRadius: 9))
            if let record = selected {
                HStack(alignment: .top, spacing: 18) {
                    ScrollView {
                        LazyVStack(spacing: 8) { ForEach(filtered) { item in
                            Button { selectedID = item.id } label: {
                                VStack(alignment: .leading, spacing: 9) {
                                    HStack { Text(item.request.algorithm.rawValue).font(.system(size: 11, weight: .bold, design: .monospaced)).foregroundStyle(Theme.blue); Text(item.request.operation.rawValue).font(.system(size: 10)).foregroundStyle(Theme.muted); Spacer() }
                                    Text(item.request.input.isEmpty ? "（空字符串）" : item.request.input.replacingOccurrences(of: "\n", with: " ")).font(.system(size: 11, design: .monospaced)).lineLimit(2).multilineTextAlignment(.leading)
                                    Text(item.createdAt.formatted(date: .numeric, time: .shortened)).font(.system(size: 10)).foregroundStyle(Theme.muted)
                                }.padding(14).frame(maxWidth: .infinity, alignment: .leading).background(.white, in: RoundedRectangle(cornerRadius: 10))
                                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(item.id == record.id ? Theme.blue.opacity(0.65) : Theme.line))
                            }.buttonStyle(.plain)
                        } }
                    }.frame(width: 225)
                    ScrollView {
                        Panel {
                            VStack(alignment: .leading, spacing: 15) {
                                HStack {
                                    Text("\(record.request.algorithm.rawValue) · \(record.request.operation.rawValue)").font(.system(size: 20, weight: .bold)); Spacer()
                                    Button { store.restore(record) } label: { Label("载入工作台", systemImage: "arrow.up.right") }.buttonStyle(.borderedProminent)
                                }
                                Text(record.createdAt.formatted(date: .long, time: .standard)).font(.system(size: 11)).foregroundStyle(Theme.muted)
                                Text(parameters(record)).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.muted).textSelection(.enabled)
                                Divider()
                                historyBlock("输入 · \(record.request.inputFormat.rawValue)", text: record.request.input)
                                historyBlock("结果 · \(record.request.outputFormat.rawValue)", text: record.output)
                                HStack { Text("\(record.inputBytes) → \(record.outputBytes) 字节 · \(record.milliseconds, specifier: "%.1f") ms").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted); Spacer(); Button("删除记录", role: .destructive) { deleteID = record.id }.font(.system(size: 11)) }
                            }
                        }
                    }
                }
            } else { EmptyState(icon: "clock.arrow.circlepath", title: store.document.history.isEmpty ? "还没有运算记录" : "没有匹配的记录", message: "在工作台开启“保存历史记录”，成功运算后自动保存。") }
            HStack { Label("本地加密存储", systemImage: "lock.fill"); Spacer(); Text("\(store.document.history.count) / 500 条") }.font(.system(size: 10)).foregroundStyle(Theme.muted)
            Spacer(minLength: 0)
        }.padding(30).padding(.top, 13)
        .alert("清空全部历史记录？", isPresented: $clearAll) {
            Button("取消", role: .cancel) {}; Button("清空", role: .destructive) { store.deleteHistory() }
        } message: { Text("本地历史将永久删除，已保存的密钥会保留。") }
        .alert("删除此记录？", isPresented: Binding(get: { deleteID != nil }, set: { if !$0 { deleteID = nil } })) {
            Button("取消", role: .cancel) { deleteID = nil }; Button("删除", role: .destructive) { if let deleteID { store.deleteHistory(deleteID) }; deleteID = nil }
        }
    }
    private func historyBlock(_ title: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack { FieldLabel(text: title); Spacer(); Button { store.copy(text) } label: { Label("复制", systemImage: "doc.on.doc") }.font(.system(size: 10)) }
            CodeEditor(text: .constant(text), readOnly: true, height: 145)
        }
    }
    private func parameters(_ record: HistoryRecord) -> String {
        let request = record.request
        if request.algorithm.isSymmetric { return "\(request.mode.rawValue) / \(request.padding.rawValue)" + (request.mode == .cbc ? "\nIV (\(request.ivFormat.rawValue)): \(request.iv)" : "") }
        if request.algorithm == .rsa { return "\(request.rsaPadding.rawValue) · \(request.resolvedKeyFormat.rawValue) 密钥" }
        if request.algorithm == .sm2 { return "ASN.1 DER / SM3 · \(request.resolvedKeyFormat.rawValue) 密钥" }
        return "\(record.outputBytes * 8) 位摘要"
    }
}
