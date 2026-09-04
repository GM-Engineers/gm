## 描述 / Description

<!-- 简明描述 PR 改动 / Concise summary of changes -->

## 相关 Issue / Related issues

<!-- 用 `Closes #N` / `Fixes #N` 语法自动关联 / Use Closes #N or Fixes #N syntax -->

## 改动类型 / Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactor (no functional change)
- [ ] Test addition / improvement
- [ ] Security fix

## 影响范围 / Scope

- [ ] 影响单个 crate / Affects a single crate
- [ ] 影响多个 crate / Affects multiple crates — 请说明 / specify:
- [ ] 仅文档 / Docs only

### 受影响 crate / Affected crates

<!-- 勾选所有相关 crate / Check all that apply -->

- [ ] `gm-tlcp`
- [ ] `gm-tls`
- [ ] `gm-crypto`
- [ ] `gm-der`
- [ ] `gm-ca`
- [ ] `gm-http-client`
- [ ] `gm-sm9-rs`
- [ ] `gm-kms`

## 测试 / Testing

- [ ] 我已运行 `cargo test -p <crate>` 且全部通过 / I ran `cargo test -p <crate>` and all pass
- [ ] 我新增了测试覆盖新代码 / I added tests covering the new code
- [ ] 我已运行 `cargo clippy -- -D warnings` / I ran clippy with warnings as errors
- [ ] 我已运行 `cargo fmt --check` / I ran cargo fmt --check
- [ ] （如适用）我已运行 GmSSL 互操作测试 / I ran GmSSL interop tests if applicable

### 测试命令 / Test commands run

```bash
# 粘贴实际运行的命令 / Paste the commands you actually ran
```

## 安全检查 / Security checklist

- [ ] 新代码**不**打印 / 记录任何私钥、PMS、随机数等密钥材料 / New code does NOT log any private keys, PMS, randoms
- [ ] 新代码**不**写入密钥材料到磁盘 / New code does NOT write key material to disk
- [ ] 常量时间比较用于签名/MAC/HMAC 验证 / Constant-time compare for signature/MAC/HMAC verify
- [ ] 关键结构体实现了 `Drop` 零化（密钥/会话/握手上下文）/ Key-bearing types zeroize on Drop

## 文档 / Documentation

- [ ] 我已更新 `CHANGELOG.md`（如适用）/ I updated CHANGELOG.md if applicable
- [ ] 我已更新 `README.md`（如适用）/ I updated README.md if applicable
- [ ] 公开 API 都有 `///` 文档注释 / All public API have `///` doc comments
- [ ] `cargo doc -p <crate> --no-deps` 无警告 / cargo doc has no warnings

## 发布影响 / Release impact

- [ ] 此 PR **不**需要 SemVer-major 升级 / This PR does NOT require a SemVer-major bump
- [ ] 此 PR **不**影响 `crates.io` 发布清单 / This PR does NOT affect crates.io publish manifest

## 附加说明 / Additional context

<!-- 截图、链接、设计讨论 / screenshots, links, design discussion -->
