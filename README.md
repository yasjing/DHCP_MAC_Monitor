# DHCP MAC Monitor

DHCP MAC Monitor 是一个面向 Windows DHCP Server 的轻量级 Web 管理工具，用于集中管理 DHCP Allow/Deny、跟踪 Lease 状态、维护固定 IP Reservation，并提供中英越三语言界面。

当前版本：**V1.8.0**  
默认端口：**8888**  
运行平台：**Windows Server x64**  
主数据存储：**SQLite（`dhcp_monitor.db`）**，异常时安全回退到旧 JSON

## V1.8.0 重点

- 首次启动自动把 `dhcp_monitor_data.json` 迁移到 SQLite。
- 迁移前自动备份，逐表核对数量，只有完整成功后才切换 SQLite 为主数据库。
- 原 JSON 不删除；SQLite 初始化或迁移失败时继续使用 JSON，避免升级导致 Web 服务无法启动。
- 审核日志使用 SQLite `LIMIT/OFFSET` 服务器端分页，默认 50 条/页，可选 20 / 50 / 100 / 200。
- 审核日志继续支持中文、English、Tiếng Việt 三语显示。
- 保留 Allow/Deny、Reservation、多 Scope/VLAN、多 Lease、回收站、CSV、三级权限等 V1.7.x 功能。
- 使用 Windows `winsqlite3.dll`，无需另外安装 SQLite、Access 或 SQL Server。

## 主要功能

- DHCP Allow / Deny 实时管理
- DHCP Lease 状态与按自然日累计在线天数
- 固定 IP Reservation 与多 Scope / VLAN 管理
- IP / Reservation / Active Lease 冲突检查
- 多 Lease 30 分钟复查与高频跨网段人员识别
- admin / operator / viewer 三级权限
- 完整审核日志与 MAC 回收站
- CSV 导入 / 导出
- 中文 / English / Tiếng Việt
- 启动诊断日志、自动备份和旧数据兼容

## 下载

已编译文件位于 `release/`：

- `DHCP_MAC_Monitor_v1.8.0_UPDATE_ONLY.zip`：现有安装升级使用。
- `DHCP_MAC_Monitor_v1.8.0_Windows_x64.zip`：完整 Windows x64 包。
- `DHCP_MAC_Monitor_v1.8.0_Windows_x64.exe`：单独 EXE。
- `SHA256.txt`：校验值。

GitHub Actions 每次主分支构建也会生成可下载的 Windows x64 artifact。

## 从 V1.7.2 升级

1. 停止当前 `DHCP_MAC_Monitor.exe`。
2. 先备份整个旧程序目录。
3. 使用 UPDATE ONLY 包时，只替换 `DHCP_MAC_Monitor.exe`。
4. **不要删除或覆盖** `config.json`、`dhcp_monitor_data.json`。
5. 右键新版 EXE，以管理员身份运行。
6. 第一次启动会创建 `dhcp_monitor.db` 并自动迁移。
7. 查看 `startup.log`；出现 `JSON -> SQLite migration complete` 与 `storage ready: SQLite (dhcp_monitor.db)` 表示迁移成功。
8. 浏览器访问 `http://服务器IP:8888`，建议第一次升级后按 `Ctrl+F5` 强制刷新。

健康检查：`http://127.0.0.1:8888/_health`

## SQLite 数据

V1.8.0 的 `dhcp_monitor.db` 包含：

- `devices`：MAC、名称、备注、在线日期、Lease、Reservation、多 Lease 状态等。
- `users`：管理账号、角色和密码哈希。
- `audit_logs`：审核日志，支持数据库分页与搜索。
- `recycle_bin`：删除 MAC 的完整恢复快照。
- `meta`：数据库版本与迁移状态。

SQLite 写入异常时，程序会记录到 `startup.log`，并尝试生成 `dhcp_monitor_emergency.json` 应急快照。

## 快速开始

1. 从 `release/` 下载完整包并解压。
2. 确认 `config.json` 中 DHCP Server 与端口设置正确。
3. 以管理员身份运行程序。
4. 浏览器访问 `http://服务器IP:8888`。
5. 首次打开时创建管理员账号。

如需开放 Windows 防火墙端口，请以管理员身份运行：

```bat
scripts\OPEN_FIREWALL_8888.bat
```

## 从源码构建

需要 Go 1.23 或更高版本，并建议直接在 Windows x64 环境构建：

```powershell
go test ./...
go build -trimpath -ldflags="-s -w" -o DHCP_MAC_Monitor.exe ./cmd/dhcp-mac-monitor
```

## 配置示例

```json
{
  "listen": "0.0.0.0",
  "port": 8888,
  "dhcp_server": "localhost",
  "poll_interval_seconds": 300,
  "deny_sync_interval_seconds": 14400
}
```

## 数据与安全

运行时数据可能包含公司内部 MAC、IP、账号哈希与审核记录。`dhcp_monitor_data.json`、`dhcp_monitor.db`、日志、备份、导入导出文件都不应提交到公开仓库。

程序建议只在可信局域网使用，不要把 8888 直接映射到公网。正式升级前始终备份当前运行目录。

## License

本仓库当前未附带开源许可证。源码公开可见，但不自动授予复制、修改或再发布权。
