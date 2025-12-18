# CQUNAL

CQUNAL 是一个面向 CQUNET 校园网的 Windows 托盘守护程序。它会定期检测当前网卡的连通性，在需要时自动发起 Portal 登录，并通过系统通知提示“网络未连接 / 登录失败 / 登录成功”以及守护、开机自启状态的变化。整个流程在后台运行，界面上只留下一个托盘图标，适合随系统启动后静默守护。

## 功能特点
- **自动探测网络**：自动枚举网卡 IP/MAC，支持根据配置择优选择接口。
- **断线重连与状态通知**：按 `check_interval` / `retry_interval` 定时检查连通性，登录成功或失败都会通过通知提示。
- **托盘守护控制**：托盘菜单可手动启动/停止守护线程，只在状态变化时弹出提示。
- **单实例 + 开机自启**：利用本地端口锁保证单实例运行，托盘菜单可勾选是否在开机时自动拉起程序。
- **安全配置**：账号/密码可通过 `config.json` 或环境变量提供，避免硬编码在脚本里。

## 环境与依赖
- 操作系统：Windows 10+
- Python：3.9 及以上
- 依赖库：`psutil`、`requests`、`pystray`、`Pillow`、`pywin32`

安装依赖：

```bash
pip install -r requirements.txt
# 或
pip install psutil requests pystray pillow pywin32
```

## 配置说明
程序启动时会在工作目录查找 `config.json`。若不存在可手动新建，格式示例：

```json
{
  "account": "202500000000",
  "password": "your-password",
  "interface": "Ethernet",        // 可选：指定网卡关键字
  "check_interval": 60,           // 成功后下一次检测的间隔（秒）
  "retry_interval": 10            // 失败后的重试间隔（秒）
}
```

- `account`/`password` 亦可使用环境变量 `CAMPUS_ACCOUNT`、`CAMPUS_PASSWORD`。
- 程序会读取同目录的 `cqulogo.png`（可自动转换为 `cqulogo.ico`，需 Pillow），也可以直接提供 `.ico`。

## 运行方式
1. 准备好 `config.json` 与图标文件，确保依赖安装完成。
2. 在项目目录执行 `python main.py`。
3. 系统托盘会出现 CQUNAL 图标，右键菜单包含：
   - **启动守护** / **停止守护**
   - **开机自启动**（勾选状态会在 `%APPDATA%/Microsoft/Windows/Start Menu/Programs/Startup/` 下生成自启脚本）
   - **退出**

程序仅在“网络状态”或“守护状态”发生变化时弹窗，避免频繁打扰。

## 打包发布
推荐使用 PyInstaller：

```bash
pyinstaller --onefile --noconsole --name "CQUNAL" --icon cqulogo.ico main.py 
```

构建完成后在 `dist/CQUNAL/` 目录得到可执行文件。分发时请同时提供 `config.json`（或给用户模板示例）以及 `cqulogo.png`/`cqulogo.ico`。

## 常见问题
- **程序提示“程序已经在运行”**：已有实例占用 `127.0.0.1:45671`。退出托盘程序后再重启即可。
- **无法定位启动目录**：`APPDATA` 环境变量缺失或权限不足，开机自启菜单会变灰并在日志中给出警告。
- **登录失败 / 网络未连接**：查看日志确认校园网是否可以访问，以及账号、密码和网卡选择是否正确。

欢迎提交 Issue 或 PR 改进本项目。
