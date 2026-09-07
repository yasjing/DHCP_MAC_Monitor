# DHCP MAC Monitor

DHCP MAC Monitor 是一个面向 Windows DHCP Server 的轻量级 Web 管理工具。它用于集中管理 DHCP Allow/Deny、跟踪 Lease 状态、维护固定 IP Reservation，并提供中英越三语言界面。

当前版本：**V1.7.1**  
默认端口：**8888**  
运行平台：**Windows Server x64**

## 主要功能

- DHCP Allow/Deny 实时管理
- DHCP Lease 状态与连续在线时间跟踪
- 按自然日累计在线天数
- 固定 IP Reservation 与多 Scope/VLAN 管理
- 重复 Lease 安全观察、清理及频繁跨网段识别
- CSV 导入与导出
- admin、operator、viewer 三级权限
- 完整操作审计和 MAC 回收站
- 中文、English、Tiếng Việt 三语言界面
- 启动自动备份和旧版本数据兼容

## 快速开始

### 使用已编译程序

1. 从 `release` 目录或 GitHub Releases 下载 Windows x64 程序。
2. 把 `configs/config.example.json` 复制到程序所在目录，并改名为 `config.json`。
3. 以管理员身份运行程序。
4. 浏览器访问 `http://服务器IP:8888`。
5. 首次打开时创建管理员账号。

如需开放 Windows 防火墙端口，请以管理员身份运行：

```bat
scripts\OPEN_FIREWALL_8888.bat
```

## 从源码构建

需要 Go 1.22 或更高版本：

```powershell
go build -trimpath -ldflags="-s -w" -o DHCP_MAC_Monitor.exe ./cmd/dhcp-mac-monitor
```

构建后，将 `config.json` 放在 EXE 同一目录中运行。

## 配置

```json
{
  "listen": "0.0.0.0",
  "port": 8888,
  "dhcp_server": "localhost",
  "poll_interval_seconds": 300,
  "deny_sync_interval_seconds": 14400
}
```

- `listen`：监听地址；局域网访问使用 `0.0.0.0`。
- `port`：Web 服务端口，默认 `8888`。
- `dhcp_server`：Windows DHCP Server 主机名或地址。
- `poll_interval_seconds`：Lease 检查周期，默认 300 秒。
- `deny_sync_interval_seconds`：Deny 同步周期，默认 14400 秒。

## 数据与隐私

程序运行后会在 EXE 所在目录生成：

- `dhcp_monitor_data.json`：账号哈希、设备、MAC、IP、审计和业务状态数据。
- `startup.log`：启动与运行异常日志。
- `backup/`：自动备份。

这些内容可能含公司内部信息，已通过 `.gitignore` 排除。**请勿手动上传到公开仓库。**

## 安全说明

- 建议只在可信局域网内使用，不要直接暴露到公网。
- 首次使用请设置强管理员密码。
- 对外提供服务时，应在前方配置 HTTPS 反向代理和访问控制。
- 升级前请备份 `config.json` 与 `dhcp_monitor_data.json`。

## 升级

通常只需停止旧程序、替换 EXE 后重新启动，并保留：

- `config.json`
- `dhcp_monitor_data.json`

V1.7.1 会自动兼容 V1.6.1 的旧数据字段。

## 许可证

本仓库当前未附带开源许可证。源码公开可见，但不自动授予复制、修改或再发布权。如需允许他人使用或参与开发，可由项目所有者后续添加 MIT、Apache-2.0 或其他许可证。
