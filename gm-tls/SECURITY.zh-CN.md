# 安全策略

**[English Version](./SECURITY.md)**

## 报告安全漏洞

如果你发现了安全漏洞，请负责任地报告：

1. **不要** 就安全问题公开提交 GitHub issue
2. 通过电子邮件联系维护者
3. 描述问题的性质与潜在影响

## 已知限制

### 1. bincode 维护状态

`bincode` v1.3.3 依赖已被标记为不再维护（RUSTSEC-2025-0141）。考虑在未来版本中迁移到替代方案：

- `postcard`
- `rkyv`
- `bitcode`

### 2. Unicode 许可证

`unicode-ident` 使用 `(MIT OR Apache-2.0) AND Unicode-3.0` 许可证。这要求同时遵守 MIT/Apache-2.0 与 Unicode License v3。如果你所在司法辖区对此有顾虑，请咨询你的法律顾问。

## 安全最佳实践

1. **始终校验证书链** —— 不要跳过校验
2. **使用唯一的 nonce** —— 每次加密使用不同的序列号
3. **保持依赖更新** —— 及时应用安全补丁
4. **使用 deny.toml** —— 在 CI/CD 中强制执行许可证与安全检查

## 依赖安全监控

- 定期运行 `cargo deny check` 审计依赖
- 监控 RUSTSEC 数据库中的安全公告
- 使用 `cargo outdated` 检查可用更新
