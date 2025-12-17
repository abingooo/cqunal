import ctypes
import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import psutil
except ImportError as exc:
    raise SystemExit(
        "需要 psutil 模块来获取网卡信息，请先运行 pip install psutil"
    ) from exc

try:
    import pystray
except ImportError as exc:
    raise SystemExit(
        "需要 pystray 来创建托盘图标，请先运行 pip install pystray"
    ) from exc

import requests

try:
    from PIL import Image
except ImportError:
    Image = None

APP_ID = "CQUNAL"
LOGIN_URL = "http://10.254.7.4:801/eportal/portal/login"
CONNECTIVITY_CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"
CONFIG_PATH = Path("config.json")
PNG_ICON_PATH = Path("cqulogo.png")
ICO_ICON_PATH = Path("cqulogo.ico")
INSTANCE_PORT = 45671
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("campus-login")

try:
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
except Exception:
    pass


def ensure_single_instance() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", INSTANCE_PORT))
        sock.listen(1)
    except OSError:
        raise SystemExit("程序已经在运行，禁止多开。")
    return sock


def _get_startup_entry_path() -> Path:
    appdata = os.getenv("APPDATA")
    if not appdata:
        raise RuntimeError("无法定位 Windows 启动目录（缺少 APPDATA 环境变量）")
    return (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / f"{APP_ID}.cmd"
    )


def _get_launch_targets() -> Tuple[Path, Path]:
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
    else:
        exe_path = Path(__file__).resolve()
    return exe_path, exe_path.parent


def _build_startup_script() -> str:
    exe_path, working_dir = _get_launch_targets()
    if getattr(sys, "frozen", False):
        launch_cmd = f'"{exe_path}"'
    else:
        interpreter = Path(sys.executable).resolve()
        launch_cmd = f'"{interpreter}" "{exe_path}"'
    lines = [
        "@echo off",
        f'cd /d "{working_dir}"',
        f'start "" {launch_cmd}',
        "",
    ]
    return "\r\n".join(lines)


def enable_autostart(entry_path: Path) -> None:
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(_build_startup_script(), encoding="utf-8")


def disable_autostart(entry_path: Path) -> None:
    try:
        entry_path.unlink()
    except FileNotFoundError:
        pass


def ensure_icon() -> Optional[str]:
    if ICO_ICON_PATH.exists():
        return str(ICO_ICON_PATH)
    if not PNG_ICON_PATH.exists():
        logger.warning("未找到 %s，继续使用默认托盘图标", PNG_ICON_PATH)
        return None
    if Image is None:
        logger.warning("需要安装 pillow 才能转换 PNG 图标，当前将使用默认图标。")
        return None
    try:
        with Image.open(PNG_ICON_PATH) as img:
            img = img.convert("RGBA")
            img.thumbnail((64, 64), Image.LANCZOS)
            img.save(ICO_ICON_PATH, format="ICO")
        logger.info("已生成托盘/通知图标 %s", ICO_ICON_PATH)
        return str(ICO_ICON_PATH)
    except Exception as exc:
        logger.warning("生成图标失败：%s", exc)
        return None


def load_icon_image() -> Optional[Image.Image]:
    path = ensure_icon()
    if not path or Image is None:
        return None
    try:
        return Image.open(path)
    except Exception as exc:
        logger.warning("加载图标失败：%s", exc)
        return None


class StatusNotifier:
    NETWORK_LABELS = {
        "network_ok": "登录成功",
        "network_missing": "网络未连接",
        "login_fail": "登录失败",
    }
    GUARD_LABELS = {
        "guard_on": "守护已启动",
        "guard_off": "守护已停止",
        "guard_running": "守护已在运行",
    }
    AUTOSTART_LABELS = {
        "autostart_on": "开机自启动：开启",
        "autostart_off": "开机自启动：关闭",
        "autostart_error": "开机自启动：异常",
    }

    def __init__(self) -> None:
        self.tray_icon: Optional[pystray.Icon] = None
        self.last_network_state: Optional[str] = None
        self.last_guard_state: Optional[str] = None
        self.last_autostart_state: Optional[str] = None

    def attach_icon(self, icon: pystray.Icon) -> None:
        self.tray_icon = icon

    def _popup(self, text: str) -> None:
        try:
            ctypes.windll.user32.MessageBoxW(
                0,
                text,
                APP_ID,
                0x00001040,
            )
        except Exception as exc:
            logger.debug("备用弹窗失败：%s", exc)

    def _notify(self, title: str, message: str) -> None:
        if self.tray_icon:
            try:
                self.tray_icon.notify(message, title=title)
                return
            except Exception as exc:
                logger.debug("托盘通知失败：%s", exc)
        self._popup(f"{title}：{message}")

    def notify_network(self, state: str, message: str, force: bool = False) -> None:
        if not force and self.last_network_state == state and self.last_network_state is not None:
            return
        self.last_network_state = state
        label = self.NETWORK_LABELS.get(state, state)
        logger.info("%s - %s", label, message)
        self._notify(label, message)

    def notify_guard(self, state: str, message: str, force: bool = False) -> None:
        if not force and self.last_guard_state == state and self.last_guard_state is not None:
            return
        self.last_guard_state = state
        label = self.GUARD_LABELS.get(state, state)
        logger.info("%s - %s", label, message)
        self._notify(label, message)

    def notify_autostart(self, state: str, message: str, force: bool = False) -> None:
        if not force and self.last_autostart_state == state and self.last_autostart_state is not None:
            return
        self.last_autostart_state = state
        label = self.AUTOSTART_LABELS.get(state, state)
        logger.info("%s - %s", label, message)
        self._notify(label, message)


def read_config() -> Dict[str, str]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"无法解析 {CONFIG_PATH}: {exc}") from exc


def load_credentials(config: Dict[str, str]) -> Tuple[str, str]:
    account = os.getenv("CAMPUS_ACCOUNT") or config.get("account")
    password = os.getenv("CAMPUS_PASSWORD") or config.get("password")
    if not account or not password:
        raise SystemExit(
            "请通过环境变量 CAMPUS_ACCOUNT/CAMPUS_PASSWORD 或 config.json 提供账号密码"
        )
    return account, password


def _sanitize_mac(mac: str) -> str:
    return mac.replace("-", "").replace(":", "").upper()


def _is_valid_ipv4(address: str) -> bool:
    if not address or address.startswith(("127.", "0.")):
        return False
    return True


def get_interface_info(preferred: Optional[str]) -> Tuple[str, str, str]:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    def normalize(name: str) -> str:
        return name.lower().strip()

    candidates: List[Tuple[str, str, str]] = []
    for name, stat in stats.items():
        if not stat.isup:
            continue
        if preferred and normalize(preferred) not in normalize(name):
            continue
        ipv4 = ""
        mac = ""
        for addr in addrs.get(name, []):
            if addr.family == socket.AF_INET and _is_valid_ipv4(addr.address):
                ipv4 = addr.address
            elif addr.family == psutil.AF_LINK:
                mac = _sanitize_mac(addr.address)
        if ipv4 and mac:
            candidates.append((name, ipv4, mac))
            if preferred:
                break

    if not candidates:
        target = preferred or "任何可用的以太网接口"
        raise RuntimeError(f"未找到满足条件的网卡：{target}")
    return candidates[0]


def build_login_params(
    account: str, password: str, ip: str, mac: str
) -> Iterable[Tuple[str, str]]:
    return [
        ("callback", "dr1004"),
        ("login_method", "1"),
        ("user_account", f",0,{account}"),
        ("user_password", password),
        ("wlan_user_ip", ip),
        ("wlan_user_ipv6", ""),
        ("wlan_user_mac", mac),
        ("wlan_ac_ip", ""),
        ("wlan_ac_name", ""),
        ("ua", DEFAULT_USER_AGENT),
        ("term_type", "1"),
        ("jsVersion", "4.2"),
        ("terminal_type", "1"),
        ("lang", "zh-cn"),
        ("v", "10095"),
        ("lang", "zh"),
    ]


def parse_jsonp(text: str) -> Dict[str, object]:
    start = text.find("(")
    end = text.rfind(")")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("返回值不是 JSONP 格式")
    payload = text[start + 1 : end]
    return json.loads(payload)


def perform_login(
    session: requests.Session, account: str, password: str, ip: str, mac: str
) -> Tuple[str, str]:
    params = build_login_params(account, password, ip, mac)
    headers = {"Referer": "http://10.254.7.4/", "User-Agent": DEFAULT_USER_AGENT}
    response = session.get(
        LOGIN_URL, params=params, headers=headers, timeout=10
    )
    response.raise_for_status()
    data = parse_jsonp(response.text)
    result = str(data.get("result", ""))
    ret_code = str(data.get("ret_code", ""))
    msg = data.get("msg", "")
    if result == "1":
        return "success", str(msg)
    if ret_code == "2":
        return "online", str(msg)
    return "failure", str(msg)


def connectivity_ok(session: requests.Session) -> bool:
    try:
        resp = session.get(
            CONNECTIVITY_CHECK_URL, timeout=5, allow_redirects=False
        )
    except requests.RequestException:
        return False
    return resp.status_code == 204


class AutoLoginWorker(threading.Thread):
    def __init__(
        self,
        notifier: StatusNotifier,
        account: str,
        password: str,
        interface_name: Optional[str],
        check_interval: int,
        retry_interval: int,
    ) -> None:
        super().__init__(daemon=True)
        self.notifier = notifier
        self.account = account
        self.password = password
        self.interface_name = interface_name
        self.check_interval = check_interval
        self.retry_interval = retry_interval
        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()
        if self.is_alive():
            self.join(timeout=5)

    def _wait(self, seconds: int) -> None:
        end = time.time() + seconds
        while not self.stop_event.is_set() and time.time() < end:
            time.sleep(0.5)

    def run(self) -> None:
        with requests.Session() as session:
            while not self.stop_event.is_set():
                if self.stop_event.is_set():
                    break
                try:
                    iface, ip, mac = get_interface_info(self.interface_name)
                except RuntimeError as exc:
                    self.notifier.notify_network("network_missing", str(exc))
                    self._wait(self.retry_interval)
                    continue

                logger.debug("当前网卡 %s IP=%s MAC=%s", iface, ip, mac)

                if connectivity_ok(session):
                    self.notifier.notify_network("network_ok", "网络已连接")
                    self._wait(self.check_interval)
                    continue

                try:
                    if self.stop_event.is_set():
                        break
                    status, message = perform_login(
                        session, self.account, self.password, ip, mac
                    )
                except requests.Timeout:
                    self.notifier.notify_network("login_fail", "登录请求超时，连接可能已断开")
                    self._wait(self.retry_interval)
                    continue
                except requests.ConnectionError:
                    self.notifier.notify_network("network_missing", "无法连接校园网服务器")
                    self._wait(self.retry_interval)
                    continue
                except Exception as exc:
                    self.notifier.notify_network("login_fail", f"登录异常：{exc}")
                    self._wait(self.retry_interval)
                    continue

                if status == "success":
                    self.notifier.notify_network("network_ok", f"登录成功：{message}", force=True)
                    self._wait(self.check_interval)
                elif status == "online":
                    self.notifier.notify_network("network_ok", f"网络已在线：{message}")
                    self._wait(self.check_interval)
                else:
                    self.notifier.notify_network("login_fail", f"登录失败：{message}")
                    self._wait(self.retry_interval)


class TrayApp:
    def __init__(
        self,
        notifier: StatusNotifier,
        account: str,
        password: str,
        interface_name: Optional[str],
        check_interval: int,
        retry_interval: int,
    ) -> None:
        self.notifier = notifier
        self.account = account
        self.password = password
        self.interface_name = interface_name
        self.check_interval = check_interval
        self.retry_interval = retry_interval

        self.worker: Optional[AutoLoginWorker] = None
        try:
            self.autostart_entry = _get_startup_entry_path()
        except RuntimeError as exc:
            logger.warning("无法启用开机自启动切换：%s", exc)
            self.autostart_entry = None
        self.autostart_enabled = bool(self.autostart_entry and self.autostart_entry.exists())
        self.icon_image = load_icon_image()
        autostart_item = pystray.MenuItem(
            "开机自启动",
            self.toggle_autostart,
            checked=lambda item: self.autostart_enabled,
            enabled=self.autostart_entry is not None,
        )
        self.icon = pystray.Icon(
            APP_ID,
            self.icon_image,
            "CQUNET AUTO LOGIN",
            menu=pystray.Menu(
                pystray.MenuItem("启动守护", self.start_worker),
                pystray.MenuItem("停止守护", self.stop_worker),
                autostart_item,
                pystray.MenuItem("退出", self.exit_app),
            ),
        )
        self.notifier.attach_icon(self.icon)

    def start_worker(self, icon=None, item=None) -> None:
        if self.worker and self.worker.is_alive():
            self.notifier.notify_guard("guard_running", "守护已在运行")
            return
        self.worker = AutoLoginWorker(
            self.notifier,
            self.account,
            self.password,
            self.interface_name,
            self.check_interval,
            self.retry_interval,
        )
        self.worker.start()
        self.notifier.notify_guard("guard_on", "守护已启动", force=True)

    def stop_worker(self, icon=None, item=None) -> None:
        if self.worker:
            self.worker.stop()
            self.worker = None
            self.notifier.notify_guard("guard_off", "已停止自动登录", force=True)

    def toggle_autostart(self, icon=None, item=None) -> None:
        if not self.autostart_entry:
            self.notifier.notify_autostart("autostart_error", "无法定位启动目录，不能设置开机自启", force=True)
            return
        try:
            if self.autostart_enabled:
                disable_autostart(self.autostart_entry)
                self.autostart_enabled = False
                self.notifier.notify_autostart("autostart_off", "将不会随开机自动启动")
            else:
                enable_autostart(self.autostart_entry)
                self.autostart_enabled = True
                self.notifier.notify_autostart("autostart_on", "已写入启动目录，将随开机启动")
        except Exception as exc:
            self.notifier.notify_autostart("autostart_error", f"切换失败：{exc}", force=True)
        finally:
            if self.icon:
                self.icon.update_menu()

    def exit_app(self, icon=None, item=None) -> None:
        self.stop_worker()
        self.icon.stop()

    def run(self) -> None:
        self.start_worker()
        self.icon.run()


def main() -> None:
    instance_socket = ensure_single_instance()
    config = read_config()
    account, password = load_credentials(config)
    interface_name = config.get("interface")
    check_interval = int(config.get("check_interval", 60))
    retry_interval = int(config.get("retry_interval", 10))

    notifier = StatusNotifier()
    logger.info(
        "托盘程序启动，网卡：%s，检测间隔：%ss，重试：%ss",
        interface_name or "自动选择",
        check_interval,
        retry_interval,
    )

    app = TrayApp(
        notifier,
        account,
        password,
        interface_name,
        check_interval,
        retry_interval,
    )
    try:
        app.run()
    finally:
        instance_socket.close()


if __name__ == "__main__":
    main()
