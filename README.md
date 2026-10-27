# 加解密工具 · Cipher Desk

原生 SwiftUI macOS 小工具，所有运算都在本机完成，运行时无需联网、Homebrew 或外部命令行程序。

## 使用

打开 `build/加解密工具.app`。可将应用拖到“应用程序”文件夹后使用。

1. 左侧选择算法，设置加密或解密及输入、输出格式。
2. 对称加密输入密钥；CBC 模式还需提供 IV。点击“随机生成”可生成密钥或 IV。解密必须使用加密时相同的密钥、IV、模式和填充。
3. RSA / SM2 可直接生成密钥对，也可先选择密钥格式再粘贴公钥或私钥。RSA 默认 XML，SM2 默认 Hex，两者均支持 PEM；切换格式会转换当前密钥。公钥用于加密，私钥用于解密。
4. 点击“开始加密 / 解密”或按 `⌘ Return`。可复制结果，或点击“结果转为输入”继续反向处理。
5. 点击“保存密钥”设置名称，后续在“选择已存密钥”或密钥库中直接载入。保存同时提供的公私钥时会检查是否配对。
6. 开启“保存历史记录”后，成功运算自动保存输入、结果和参数。历史页面支持搜索、算法筛选、查看、复制、载入和删除；载入不会自动重新执行。

快捷键：`⌘ 1` 工作台，`⌘ 2` 密钥库，`⌘ 3` 历史记录。

## 算法与格式

| 算法 | 支持能力 | 参数 |
| --- | --- | --- |
| MD5 | 单向摘要 | 128 位 |
| SHA-256 | 单向摘要 | 256 位 |
| DES | 加密、解密 | 8 字节密钥；CBC / ECB |
| 3DES | 加密、解密 | 16 / 24 字节密钥；CBC / ECB |
| AES | 加密、解密 | 16 / 24 / 32 字节密钥；CBC / ECB |
| RSA | 生成密钥对、加密、解密 | 2048 / 3072 / 4096 位；OAEP SHA-256（MGF1 SHA-256）或 PKCS#1 v1.5 |
| SM2 | 生成密钥对、加密、解密 | sm2p256v1；SM3；ASN.1 DER 密文 |
| SM3 | 单向摘要 | 256 位 |
| SM4 | 加密、解密 | 16 字节密钥；CBC / ECB |

- 输入和输出支持 UTF-8、标准 Base64、Hex。密钥和 IV 可分别设置格式。
- Hex 大小写不敏感，可含空白和 `0x` 前缀；Base64 可含换行，需保留标准填充。
- 密钥长度按解码后的**字节数**判断，中文字符通常不止一个字节。随机二进制密钥 / IV 自动采用 Hex，避免无法表示为 UTF-8。
- 对称算法支持 PKCS7 和 NoPadding。DES 的 PKCS7 在 8 字节分组上与常见 PKCS5Padding 兼容。NoPadding 的输入必须是分组长度的整数倍。
- DES 使用 ECB 时不需要 IV；CBC 时必须提供 8 字节 IV，解密时与加密时保持一致。
- MD5、SM3、SHA-256 是摘要算法，无法解密；DES、3DES、MD5 主要用于兼容既有接口。
- SM2 Hex 私钥为 32 字节（64 个十六进制字符）；公钥生成时输出 `04 + X + Y`，共 65 字节（130 个字符）。导入也支持不带 `04` 的 `X + Y`（128 个字符），大小写不敏感，可带 `0x` 前缀及空白。会验证私钥范围、公钥曲线及公私钥配对。
- RSA XML 使用 .NET `RSAKeyValue`：公钥包含 `Modulus`、`Exponent`；私钥还包含 `P`、`Q`、`DP`、`DQ`、`InverseQ`、`D`。各字段为无符号大端整数的标准 Base64，导出保持 .NET 所需的参数宽度。拒绝重复字段、外部实体和无效密钥参数。
- PEM 密钥生成输出 SPKI 公钥及未设置口令的 PKCS#8 私钥；从 RSA XML 转为 PEM 时私钥采用 PKCS#1，工具也支持该格式。不支持带口令的 PEM、压缩 SM2 Hex 公钥或裸 C1C3C2 / C1C2C3 密文；SM2 密钥格式不改变 ASN.1 DER 密文格式。
- 密钥格式随密钥库和历史参数保存；1.0 版本的 PEM 密钥及历史记录继续兼容。
- RSA 处理单个数据块，不自动分段。最大明文字节数：OAEP 为 `密钥字节数 - 66`；PKCS#1 为 `密钥字节数 - 11`。2048 位密钥分别为 190 / 245 字节。
- 单次输入上限为解码后的 1 MiB。二进制结果不能表示为 UTF-8 时会提示改用 Base64 / Hex。

## 本地数据

- 数据位于 `~/Library/Application Support/CipherDesk/vault.enc`，采用 AES-256-GCM 加密并验证完整性。
- 主密钥由 macOS 登录钥匙串保存，服务名为 `cn.mky.CipherDesk.local-vault`，仅当前设备解锁后可读取。不要删除该钥匙串条目，否则已有数据无法解密。
- 目录权限为 `0700`，文件权限为 `0600`；应用不创建明文密钥临时文件，不将密钥作为子进程参数，也不发送网络请求。
- 历史记录最多 500 条，输入与输出文本合计最多 20 MiB，超限淘汰较早记录。历史不保存密钥原文；如果使用过已保存的密钥，会记录其引用，重新载入时尝试恢复。手动输入但未保存的密钥需重新提供。
- 解锁或完整性验证失败时保留原文件并停止持久化，工作台仍可运算。密钥 / 历史删除需确认，无法撤销。
- 复制功能使用系统剪贴板。私钥在界面默认隐藏，可点击眼睛查看。

## 从源码构建

要求 macOS 14+，Apple Command Line Tools（含 Swift 5.9+、Clang、make、Perl），以及系统 curl、Python 3。当前产物为 Apple Silicon arm64；构建脚本也支持在 Intel Mac 上编译 x86_64，不宣称为通用二进制。

```bash
bash Scripts/build-app.sh
bash Scripts/test.sh
open 'build/加解密工具.app'
```

首次构建下载并核验 OpenSSL 3.5.9 源码，静态编译至 `Vendor/openssl/`；后续构建复用已有依赖。下载和编译中间文件位于 `work/`，Swift 中间产物位于 `.build/`。离线运行的 `.app` 无需这些目录。

`Scripts/test.sh` 运行 15 组独立核心测试，不依赖 Xcode / XCTest。覆盖摘要及分组加密的标准向量、全部对称模式与密钥长度、RSA / SM2 往返和错误密钥、RSA 长度边界、格式校验、密钥配对、密钥与历史的加密存储 / 读回 / 删除，以及篡改检测；另验证 SM2 Hex / PEM 和 RSA XML / PEM 双向转换及跨格式加解密、非法参数、XML 解析限制和旧记录兼容性。测试使用临时目录和内存中的测试主密钥，结束后清理，不访问用户的密钥库。

构建脚本先在 `work/app-build.*` 中完整生成、签名并校验应用，再替换 `build/加解密工具.app`。已有应用会暂存为该次构建目录下的 `previous.app`；当前运行进程和输入不受强制关闭，退出并重新打开后使用新版本。

默认使用本机临时签名（ad-hoc），未做 Apple 开发者签名及公证。用于分发时，可通过 `CIPHERDESK_SIGN_IDENTITY` 指定已有签名身份，再按 Apple 的要求完成公证；本项目不自动发布或安装到系统目录。

加密实现采用 OpenSSL EVP API，并静态包含 default / legacy provider。使用应用独立的 library context，不修改系统 OpenSSL 配置。OpenSSL 以 Apache 2.0 许可使用，其许可位于应用 `Contents/Resources/OpenSSL-LICENSE.txt`。

参考：[OpenSSL 下载与维护版本](https://openssl-library.org/source/)、[SM4 EVP API](https://docs.openssl.org/3.0/man7/EVP_CIPHER-SM4/)、[legacy provider](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/)、[EVP 密钥参数导入](https://docs.openssl.org/3.5/man3/EVP_PKEY_fromdata/)、[.NET RSA 参数](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsaparameters)。
