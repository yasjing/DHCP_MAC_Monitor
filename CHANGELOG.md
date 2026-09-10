# Changelog

## V1.8.0 — 2026-09-10

### SQLite 数据迁移

- 核心数据从单一 `dhcp_monitor_data.json` 升级为 SQLite 主存储 `dhcp_monitor.db`。
- 第一次启动先创建 `backup/before_sqlite_YYYYMMDD_HHMMSS/` 迁移前备份。
- 事务导入设备、账号、审核日志和 MAC 回收站，并逐表核对记录数量。
- 只有全部验证成功后才把 SQLite 标记为主数据库。
- SQLite 初始化、读取或迁移失败时继续使用 JSON，不阻止 8888 Web 服务启动。
- 原 `dhcp_monitor_data.json` 不删除、不覆盖，保留作为迁移前回退依据。
- SQLite 保存异常时记录 `startup.log` 并尝试生成 `dhcp_monitor_emergency.json`。
- 启动备份同时支持 `dhcp_monitor.db`、`-wal`、`-shm`。

### 审核日志

- 审核日志使用 SQLite 独立表保存。
- 服务端 `LIMIT/OFFSET` 分页，默认 50 条/页，可选 20 / 50 / 100 / 200。
- 搜索在服务器端执行，避免浏览器一次加载全部历史日志。
- 中文、English、Tiếng Việt 三语显示继续保留。

### 兼容性

- 保留 V1.7.2 的 Allow/Deny、固定 IP Reservation、多 Scope/VLAN、多 Lease、回收站、CSV 和三级权限逻辑。
- 默认端口继续使用 8888。
- 使用 Windows `winsqlite3.dll`，无需额外安装 SQLite / Access / SQL Server。
- Go 构建版本升级到 1.23。

## V1.7.2

- 审核日志改为服务器端分页。
- 审核日志增加中 / 英 / 越三语显示。
- 主要业务审核动作和常见详情增加对应语言映射。
- Windows / PowerShell 原始错误信息保留原文，避免翻译后失真。

## V1.7.1

- 修复 V1.7.0 静默退出问题。
- 增加 `startup.log`、panic 捕获和端口监听错误日志。
- 保留固定 IP、MAC 回收站、多 Lease 人员和 30 分钟复查等功能。
