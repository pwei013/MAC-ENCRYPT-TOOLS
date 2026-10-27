import SwiftUI
import CryptoCore

struct WorkbenchView: View {
    @EnvironmentObject var store: AppStore
    @ViewState private var saveSheet = false
    @ViewState private var keyName = ""
    @ViewState private var showPrivateKey = false
    private var algorithm: Algorithm { store.request.algorithm }
    private var matchingKeys: [KeyRecord] { store.document.keys.filter { $0.algorithm == algorithm } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                PageHeading(eyebrow: "CRYPTO WORKSPACE", title: "加解密工作台", subtitle: "在一个工作台里，完成文本加解密与摘要计算。")
                configuration
                if !algorithm.isDigest { keyPanel }
                HStack(alignment: .top, spacing: 16) {
                    inputPanel
                    outputPanel
                }
                actionBar
                if let notice = store.notice {
                    Label(notice, systemImage: "checkmark.circle.fill").font(.system(size: 11)).foregroundStyle(Color.teal)
                }
                HStack(spacing: 6) {
                    Image(systemName: "lock.shield"); Text("运算在本机完成。历史最多保留 500 条，不记录未保存的密钥。")
                }.font(.system(size: 10)).foregroundStyle(Theme.muted)
            }.padding(24).padding(.top, 13)
        }
        .disabled(store.busy)
        .sheet(isPresented: $saveSheet) {
            VStack(alignment: .leading, spacing: 18) {
                Text("保存密钥").font(.system(size: 21, weight: .bold))
                Text("保存后可在密钥库或工作台直接选择使用。").font(.system(size: 12)).foregroundStyle(Theme.muted)
                TextField("密钥名称，例如：测试环境 RSA", text: $keyName).textFieldStyle(.roundedBorder)
                HStack { Spacer(); Button("取消") { saveSheet = false }.keyboardShortcut(.cancelAction)
                    Button("保存到本地") { if store.saveKey(name: keyName) { saveSheet = false } }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                }
            }.padding(26).frame(width: 430)
        }
        .onChange(of: store.request) { _, _ in store.result = nil }
        .onChange(of: store.request.algorithm) { _, _ in showPrivateKey = false }
    }
    private var configuration: some View {
        Panel {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    HStack(spacing: 10) {
                        Text(algorithm.rawValue).font(.system(size: 18, weight: .bold, design: .monospaced))
                        Text(algorithm.category).font(.system(size: 10, weight: .medium)).foregroundStyle(Theme.blue)
                            .padding(.horizontal, 8).padding(.vertical, 4).background(Theme.blue.opacity(0.07), in: Capsule())
                    }
                    Spacer()
                    if algorithm.isDigest {
                        Label("计算摘要", systemImage: "number").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.muted)
                    } else {
                        Picker("操作", selection: Binding(get: { store.request.operation }, set: { store.setOperation($0) })) {
                            Text("加密").tag(CryptoOperation.encrypt); Text("解密").tag(CryptoOperation.decrypt)
                        }.pickerStyle(.segmented).frame(width: 170)
                    }
                }
                if !algorithm.isSymmetric { Text(algorithm.detail).font(.system(size: 11)).foregroundStyle(Theme.muted) }
                if algorithm.isSymmetric {
                    HStack(spacing: 24) {
                        HStack { FieldLabel(text: "分组模式"); Picker("分组模式", selection: $store.request.mode) { ForEach(BlockMode.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.labelsHidden().frame(width: 110) }
                        HStack { FieldLabel(text: "填充方式"); Picker("填充方式", selection: $store.request.padding) { ForEach(Padding.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.labelsHidden().frame(width: 140) }
                        Spacer()
                        if algorithm == .des || algorithm == .tripleDES { Label("适用于旧接口兼容", systemImage: "info.circle").font(.system(size: 10)).foregroundStyle(Theme.muted) }
                    }
                } else if algorithm == .rsa {
                    HStack { FieldLabel(text: "RSA 填充"); Picker("RSA 填充", selection: $store.request.rsaPadding) { ForEach(RSAPadding.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.labelsHidden().frame(width: 210); Spacer() }
                } else if algorithm.isDigest {
                    Text("摘要是单向校验值，无法解密还原。").font(.system(size: 11)).foregroundStyle(Theme.muted)
                }
            }
        }
    }
    private var keyPanel: some View {
        Panel {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Label("密钥配置", systemImage: "key.horizontal").font(.system(size: 12, weight: .semibold))
                    Spacer()
                    Menu {
                        if matchingKeys.isEmpty { Text("此算法暂无已保存密钥") }
                        ForEach(matchingKeys) { key in Button(key.name) { store.applyKey(key) } }
                    } label: { Label("选择已存密钥", systemImage: "tray") }.menuStyle(.borderlessButton).fixedSize().font(.system(size: 11))
                    Button { keyName = "\(algorithm.rawValue) 密钥"; saveSheet = true } label: { Label("保存密钥", systemImage: "square.and.arrow.down") }.font(.system(size: 11)).disabled(!store.storageReady)
                }
                if algorithm.isAsymmetric { asymmetricKeys } else { symmetricKeys }
            }
        }
    }
    private var symmetricKeys: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                FieldLabel(text: "密钥 Key").frame(width: 62, alignment: .leading)
                SecretField(text: $store.request.key, title: algorithm.detail)
                formatPicker("密钥格式", selection: $store.request.keyFormat)
                Button { store.generate() } label: { Label("随机生成", systemImage: "arrow.triangle.2.circlepath") }.frame(height: 36).font(.system(size: 11))
            }
            if store.request.mode == .cbc {
                HStack(spacing: 10) {
                    FieldLabel(text: "向量 IV").frame(width: 62, alignment: .leading)
                        TextField("需要 \(algorithm.blockBytes) 字节；加密时可随机生成，解密时使用相同 IV", text: $store.request.iv)
                            .textFieldStyle(.plain).font(.system(size: 11, design: .monospaced)).padding(11).background(Theme.background, in: RoundedRectangle(cornerRadius: 7))
                    formatPicker("IV 格式", selection: $store.request.ivFormat)
                    Button { store.randomIV() } label: { Label("随机生成", systemImage: "shuffle") }.frame(height: 36).font(.system(size: 11))
                }
            }
        }
    }
    private var asymmetricKeys: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                FieldLabel(text: "密钥格式")
                Picker("密钥对格式", selection: Binding(get: { store.request.resolvedKeyFormat }, set: { store.setKeyFormat($0) })) {
                    ForEach(AsymmetricKeyFormat.supported(for: algorithm)) { Text($0.rawValue).tag($0) }
                }.labelsHidden().frame(width: 100).controlSize(.small)
                Spacer()
                if algorithm == .rsa { Picker("密钥长度", selection: $store.rsaBits) { ForEach([2048,3072,4096], id: \.self) { Text("\($0) 位").tag($0) } }.labelsHidden().frame(width: 105) }
                Button { store.generate() } label: { Label("生成密钥对", systemImage: "plus.circle") }.font(.system(size: 11))
            }
            Text(keyFormatHint).font(.system(size: 10)).foregroundStyle(Theme.muted)
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 7) {
                    HStack { FieldLabel(text: "公钥 · 用于加密"); Spacer(); Button { store.copy(store.request.publicKey) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.plain).help("复制公钥").disabled(store.request.publicKey.isEmpty) }
                    CodeEditor(text: $store.request.publicKey, placeholder: publicKeyPlaceholder, height: 91)
                }
                VStack(alignment: .leading, spacing: 7) {
                    HStack {
                        FieldLabel(text: "私钥 · 用于解密"); Spacer()
                        Button { showPrivateKey.toggle() } label: { Image(systemName: showPrivateKey ? "eye.slash" : "eye") }.buttonStyle(.plain).help("显示或隐藏私钥")
                        Button { store.copy(store.request.privateKey) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.plain).help("复制私钥").disabled(store.request.privateKey.isEmpty)
                    }
                    if showPrivateKey {
                        CodeEditor(text: $store.request.privateKey, placeholder: privateKeyPlaceholder, height: 91)
                    } else {
                        VStack(spacing: 8) {
                            Image(systemName: "lock.fill").foregroundStyle(Theme.muted)
                            Button(store.request.privateKey.isEmpty ? "点击粘贴或编辑私钥" : "私钥已载入 · 点击查看或编辑") { showPrivateKey = true }.buttonStyle(.plain).font(.system(size: 11)).foregroundStyle(Theme.muted)
                        }.frame(maxWidth: .infinity).frame(height: 105).background(Theme.background, in: RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
        }
    }
    private var keyFormatHint: String {
        switch store.request.resolvedKeyFormat {
        case .pem: "公钥 SPKI / 私钥 PKCS#8 或 RSA PKCS#1；切换格式会转换当前密钥"
        case .hex: "SM2 公钥：04 + X + Y（130 个字符，也接受 128 个）；私钥：64 个十六进制字符"
        case .xml: ".NET RSAKeyValue 格式，字段内容为 Base64；切换格式会转换当前密钥"
        }
    }
    private var publicKeyPlaceholder: String {
        switch store.request.resolvedKeyFormat {
        case .pem: "-----BEGIN PUBLIC KEY-----"
        case .hex: "04 + 64 个字符的 X + 64 个字符的 Y，也可不带 04"
        case .xml: "<RSAKeyValue>\n  <Modulus>…</Modulus>\n  <Exponent>…</Exponent>\n</RSAKeyValue>"
        }
    }
    private var privateKeyPlaceholder: String {
        switch store.request.resolvedKeyFormat {
        case .pem: "-----BEGIN PRIVATE KEY-----"
        case .hex: "64 个十六进制字符的私钥"
        case .xml: "<RSAKeyValue>\n  Modulus、Exponent、P、Q、DP、DQ、InverseQ、D\n</RSAKeyValue>"
        }
    }
    private var inputPanel: some View {
        Panel {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("输入内容", systemImage: "text.alignleft").font(.system(size: 12, weight: .semibold))
                    Spacer(); formatPicker("输入格式", selection: $store.request.inputFormat)
                }
                CodeEditor(text: $store.request.input, placeholder: store.request.operation == .decrypt ? "粘贴需要解密的密文…" : "输入需要处理的字符串…", height: 145)
                HStack {
                    Text("\(store.request.input.count) 字符").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted)
                    Spacer(); Button("清空") { store.request.input = ""; store.result = nil }.buttonStyle(.plain).font(.system(size: 10)).foregroundStyle(Theme.muted)
                }
            }
        }
    }
    private var outputPanel: some View {
        Panel {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("输出结果", systemImage: "chevron.left.forwardslash.chevron.right").font(.system(size: 12, weight: .semibold))
                    Spacer(); formatPicker("输出格式", selection: $store.request.outputFormat)
                }
                ZStack {
                    CodeEditor(text: .constant(store.result?.text ?? ""), placeholder: "执行后，结果会显示在这里", readOnly: true, height: 145)
                    if store.busy { ProgressView().controlSize(.small).frame(maxWidth: .infinity, maxHeight: .infinity).background(.white.opacity(0.8)) }
                }
                HStack {
                    if let result = store.result {
                        Text("\(result.inputBytes) → \(result.outputBytes) 字节 · \(result.milliseconds, specifier: "%.1f") ms").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted)
                    } else { Text("等待执行").font(.system(size: 10)).foregroundStyle(Theme.muted) }
                    Spacer()
                    Button { if let result = store.result { store.copy(result.text) } } label: { Label("复制", systemImage: "doc.on.doc") }.buttonStyle(.plain).font(.system(size: 10)).foregroundStyle(Theme.blue).disabled(store.result == nil)
                }
            }
        }
    }
    private var actionBar: some View {
        HStack(spacing: 14) {
            Button { store.run() } label: {
                HStack(spacing: 13) {
                    Image(systemName: "play.fill").font(.system(size: 10))
                    Text(store.busy ? "正在处理…" : algorithm.isDigest ? "计算摘要" : "开始\(store.request.operation.rawValue)").font(.system(size: 12, weight: .semibold))
                    Text("⌘ ↩").font(.system(size: 11)).opacity(0.6)
                }.padding(.horizontal, 17).padding(.vertical, 11).background(Theme.blue, in: RoundedRectangle(cornerRadius: 8)).foregroundStyle(.white)
            }.buttonStyle(.plain)
            if !algorithm.isDigest {
                Button { store.useOutput() } label: { Label("结果转为输入", systemImage: "arrow.uturn.backward") }.font(.system(size: 11)).disabled(store.result == nil)
            }
            Spacer()
            Toggle("保存历史记录", isOn: $store.rememberHistory).toggleStyle(.switch).controlSize(.small).font(.system(size: 11)).disabled(!store.storageReady)
        }
    }
    private func formatPicker(_ title: String, selection: Binding<TextFormat>) -> some View {
        Picker(title, selection: selection) { ForEach(TextFormat.allCases) { Text($0.rawValue).tag($0) } }.labelsHidden().frame(width: 96).controlSize(.small)
    }
}
