import SwiftUI
import AppKit
import CryptoCore

// Select the property-wrapper type explicitly. This also works with CLT SDKs
// that expose the newer State macro without bundling SwiftUIMacros.
typealias ViewState<Value> = SwiftUI.State<Value>

@main struct CipherDeskApp: App {
    @StateObject private var store = AppStore()
    var body: some Scene {
        WindowGroup("加解密工具") {
            ContentView().environmentObject(store)
                .frame(minWidth: 1080, minHeight: 760)
                .preferredColorScheme(.light)
                .onAppear { NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
        }
        .defaultSize(width: 1220, height: 880)
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("工具") {
                Button("执行运算") { if store.route == .workbench { store.run() } }.keyboardShortcut(.return, modifiers: .command).disabled(store.busy)
                Button("加解密工作台") { store.route = .workbench }.keyboardShortcut("1", modifiers: .command).disabled(store.busy)
                Button("密钥库") { store.route = .keys }.keyboardShortcut("2", modifiers: .command).disabled(store.busy)
                Button("历史记录") { store.route = .history }.keyboardShortcut("3", modifiers: .command).disabled(store.busy)
            }
        }
    }
}

enum Theme {
    static let ink = Color(red: 0.11, green: 0.16, blue: 0.25)
    static let muted = Color(red: 0.45, green: 0.50, blue: 0.59)
    static let blue = Color(red: 0.20, green: 0.36, blue: 0.94)
    static let background = Color(red: 0.96, green: 0.97, blue: 0.985)
    static let line = Color(red: 0.88, green: 0.90, blue: 0.94)
    static let sidebar = Color(red: 0.94, green: 0.95, blue: 0.97)
}

struct ContentView: View {
    @EnvironmentObject var store: AppStore
    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 206)
            Rectangle().fill(Theme.line).frame(width: 1)
            VStack(spacing: 0) {
                if !store.storageReady {
                    HStack {
                        Label("本地数据未解锁，密钥和历史暂不能保存。", systemImage: "lock.trianglebadge.exclamationmark")
                        Spacer(); Button("重新解锁") { store.unlock() }
                    }.font(.system(size: 12)).padding(12).background(Color.orange.opacity(0.12))
                }
                switch store.route {
                case .workbench: WorkbenchView()
                case .keys: KeysView()
                case .history: HistoryView()
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Theme.background)
        }
        .tint(Theme.blue).foregroundStyle(Theme.ink)
        .alert("操作提示", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("知道了", role: .cancel) { store.error = nil }
        } message: { Text(store.error ?? "") }
    }
    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 11).fill(Theme.blue).frame(width: 38, height: 38)
                    Image(systemName: "lock.shield.fill").font(.system(size: 21)).foregroundStyle(.white)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text("加解密工具").font(.system(size: 16, weight: .bold))
                    Text("CIPHER DESK").font(.system(size: 9, weight: .semibold, design: .monospaced)).tracking(1.8).foregroundStyle(Theme.muted)
                }
            }.padding(.top, 42).padding(.bottom, 30).padding(.horizontal, 19)
            ScrollView {
                VStack(alignment: .leading, spacing: 5) {
                    sectionLabel("工作空间")
                    navButton("加解密工作台", icon: "square.grid.2x2", route: .workbench)
                    navButton("密钥库", icon: "key.horizontal", route: .keys, count: store.document.keys.count)
                    navButton("历史记录", icon: "clock.arrow.circlepath", route: .history, count: store.document.history.count)
                    sectionLabel("算法").padding(.top, 22)
                    ForEach([Algorithm.aes, .des, .tripleDES, .rsa, .sm2, .sm4, .md5, .sm3, .sha256]) { algorithm in
                        Button { store.select(algorithm) } label: {
                            HStack(spacing: 10) {
                                Circle().fill(algorithm.rawValue.hasPrefix("SM") ? Color.teal : Theme.muted.opacity(0.5)).frame(width: 5, height: 5)
                                Text(algorithm.rawValue).font(.system(size: 12, weight: store.request.algorithm == algorithm ? .semibold : .regular, design: .monospaced))
                                Spacer()
                                if algorithm.isDigest { Text("摘要").font(.system(size: 10)).foregroundStyle(Theme.muted) }
                                if store.request.algorithm == algorithm && store.route == .workbench { Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundStyle(Theme.blue) }
                            }.padding(.horizontal, 14).padding(.vertical, 8).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                    }
                }.padding(.horizontal, 12)
            }
            VStack(alignment: .leading, spacing: 7) {
                Label("全程离线 · 本地保存", systemImage: "checkmark.shield").font(.system(size: 11, weight: .medium)).foregroundStyle(Color.teal)
                Text("密钥与历史使用本机钥匙串保护").font(.system(size: 10)).foregroundStyle(Theme.muted)
                Text("v1.1.0  /  macOS").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted.opacity(0.8))
            }.padding(20)
        }.background(Theme.sidebar).disabled(store.busy)
    }
    private func sectionLabel(_ title: String) -> some View { Text(title).font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.muted).padding(.horizontal, 13).padding(.bottom, 6) }
    private func navButton(_ title: String, icon: String, route: Route, count: Int? = nil) -> some View {
        let active = store.route == route
        return Button { store.route = route } label: {
            HStack(spacing: 10) {
                Image(systemName: icon).font(.system(size: 14)).frame(width: 17)
                Text(title).font(.system(size: 12, weight: active ? .semibold : .regular)); Spacer()
                if let count { Text("\(count)").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted) }
            }.padding(.horizontal, 12).padding(.vertical, 11)
                .foregroundStyle(active ? Theme.blue : Theme.ink)
                .background(active ? Color.white : Color.clear, in: RoundedRectangle(cornerRadius: 8))
                .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }
}

struct PageHeading: View {
    let eyebrow: String, title: String, subtitle: String
    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 7) {
                Text(eyebrow).font(.system(size: 10, weight: .semibold, design: .monospaced)).tracking(2).foregroundStyle(Theme.muted)
                Text(title).font(.system(size: 27, weight: .bold))
                Text(subtitle).font(.system(size: 12)).foregroundStyle(Theme.muted)
            }
            Spacer()
            Label("本地运行", systemImage: "circle.fill").font(.system(size: 10, weight: .medium)).foregroundStyle(Color.teal)
                .padding(.horizontal, 11).padding(.vertical, 7).background(Color.teal.opacity(0.07), in: Capsule()).padding(.top, 12)
        }
    }
}

struct Panel<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        content.padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(.white, in: RoundedRectangle(cornerRadius: 13))
            .overlay(RoundedRectangle(cornerRadius: 13).stroke(Theme.line, lineWidth: 1))
    }
}

struct FieldLabel: View {
    let text: String
    var body: some View { Text(text).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.muted) }
}

struct CodeEditor: View {
    @Binding var text: String
    var placeholder: String = ""
    var readOnly = false
    var height: CGFloat = 200
    var body: some View {
        ZStack(alignment: .topLeading) {
            if text.isEmpty { Text(placeholder).font(.system(size: 12, design: .monospaced)).foregroundStyle(Theme.muted.opacity(0.65)).padding(.horizontal, 6).padding(.vertical, 8).allowsHitTesting(false) }
            if readOnly {
                ScrollView { Text(text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(6) }
            } else {
                TextEditor(text: $text).font(.system(size: 12, design: .monospaced)).scrollContentBackground(.hidden)
                    .autocorrectionDisabled()
            }
        }.frame(height: height).padding(7).background(Theme.background.opacity(0.7), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct SecretField: View {
    @Binding var text: String
    let title: String
    @ViewState private var revealed = false
    var body: some View {
        HStack {
            Group { if revealed { TextField(title, text: $text) } else { SecureField(title, text: $text) } }
                .textFieldStyle(.plain).font(.system(size: 12, design: .monospaced))
            Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye").foregroundStyle(Theme.muted) }.buttonStyle(.plain).help(revealed ? "隐藏密钥" : "显示密钥")
        }.padding(11).background(Theme.background, in: RoundedRectangle(cornerRadius: 7))
    }
}

struct EmptyState: View {
    let icon: String, title: String, message: String
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: icon).font(.system(size: 35, weight: .light)).foregroundStyle(Theme.blue.opacity(0.65))
            Text(title).font(.system(size: 16, weight: .semibold))
            Text(message).font(.system(size: 12)).foregroundStyle(Theme.muted).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity, minHeight: 290)
    }
}
