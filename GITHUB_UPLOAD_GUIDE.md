# 上传到 GitHub

## 1. 创建公开仓库

登录 GitHub，点击 **New repository**，建议填写：

- Repository name：`DHCP-MAC-Monitor`
- Visibility：`Public`
- 不勾选自动创建 README、.gitignore 或 License

## 2. 上传本项目

在解压后的项目根目录打开 PowerShell，执行：

```powershell
git init
git add .
git commit -m "Initial public release v1.7.1"
git branch -M main
git remote add origin https://github.com/你的GitHub用户名/DHCP-MAC-Monitor.git
git push -u origin main
```

GitHub 要求登录时，请使用浏览器授权或 Personal Access Token，不要输入 GitHub 账号密码。

## 3. 后续更新

```powershell
git add .
git commit -m "说明本次修改内容"
git push
```

## 4. 公开前检查

执行：

```powershell
git status
git ls-files
```

确认列表中没有以下内容：

- `dhcp_monitor_data.json`
- `startup.log`
- `backup` 文件夹
- 实际运行使用的 `config.json`
- 公司员工、MAC、IP、账号或审计数据

## 5. 发布 EXE（可选）

在 GitHub 仓库右侧点击 **Releases → Create a new release**，Tag 填写 `v1.7.1`，上传 `release` 目录中的 EXE 和 SHA256 文件。
