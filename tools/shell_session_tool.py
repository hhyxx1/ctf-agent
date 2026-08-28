"""持久化 shell 会话工具（T2-⑤）：shell_open / shell_send / shell_read / shell_close

解决 run_shell 无状态 subprocess 的短板——CTF 大量场景需要交互式状态：
- pwn：本地调试进程（发 payload → 读回显 → 调 payload）
- misc：nc 连上后的多步交互、数据库连接后的多步查询
- web：ssh 上去后的探索、redis 交互

实现：pty 伪终端 + select 非阻塞读，无外部依赖。每个会话保留最近 200KB 输出。
"""
import os
import pty
import select
import signal
import subprocess
import threading
import time

from tools.base import register_tool, _check_external_access

# 会话表：session_id -> _ShellSession（含锁保护；agent 线程并发访问）
_SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()
_SESSIONS_ORDER = []  # 会话创建顺序（超出上限时关最旧用）
_SESSION_SEQ = [0]
_MAX_SESSIONS = 8          # 最多同时 8 个会话（超出关最旧）
_MAX_BUFFER = 200 * 1024   # 每会话保留最近 200KB 输出


class _ShellSession:
    def __init__(self, command: str, cwd: str = None):
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(
            command, shell=True, cwd=cwd,
            stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True,  # 独立进程组，关闭时可整组杀
        )
        os.close(slave)  # 父进程侧只留 master
        self.buffer = ""
        self.lock = threading.Lock()

    def _read_available(self, timeout: float = 0.0):
        """非阻塞读 master 上可用的输出，追加进 buffer"""
        end = time.time() + timeout
        while True:
            remain = end - time.time()
            if remain < 0 and timeout > 0:
                break
            try:
                r, _, _ = select.select([self.master], [], [], max(0.05, remain if timeout > 0 else 0.05))
            except (OSError, ValueError):
                break
            if self.master not in r:
                if timeout <= 0:
                    break
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError:
                break  # 进程已退出/管道关闭
            if not data:
                break
            self.buffer += data.decode("utf-8", errors="replace")
            # 缓冲超限：保留尾部
            if len(self.buffer) > _MAX_BUFFER:
                self.buffer = self.buffer[-_MAX_BUFFER:]
            if timeout <= 0:
                break

    def read(self, wait_seconds: float = 2.0) -> str:
        with self.lock:
            self._read_available(wait_seconds)
            out = self.buffer
            self.buffer = ""
            return out

    def send(self, text: str):
        with self.lock:
            os.write(self.master, text.encode("utf-8"))

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self):
        """杀整个进程组并释放 fd"""
        try:
            if self.proc.poll() is None:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                self.proc.wait(timeout=3)
        except Exception:
            pass
        try:
            os.close(self.master)
        except OSError:
            pass


def _get_session(session_id: str) -> _ShellSession:
    sess = _SESSIONS.get(str(session_id))
    if not sess:
        raise KeyError(f"会话 {session_id} 不存在（已关闭或从未创建）。用 shell_list 查看现有会话。")
    return sess


def _new_session_id() -> str:
    _SESSION_SEQ[0] += 1
    return f"s{_SESSION_SEQ[0]}"


@register_tool(
    name="shell_open",
    description="打开一个持久化交互式 shell 会话（进程保持存活，状态跨调用保留）。"
                "适合：pwn 本地调试进程、nc/数据库/ssh 交互、需要多步输入的场景。"
                "之后用 shell_send 发输入、shell_read 读输出、shell_close 关闭。",
    parameters={
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "启动命令，如 './pwn_binary'、'nc host port'、'mysql -u root -p db'"},
            "wait_seconds": {"type": "number", "description": "启动后等待输出的秒数（默认 2）"},
        },
        "required": ["command"],
    },
)
def shell_open(command: str, wait_seconds: float = 2.0) -> str:
    block = _check_external_access(command)
    if block:
        return block
    try:
        sid = _new_session_id()
        # 超出上限时关最旧（在锁外做 close 防死锁，简单起见直接覆盖最旧）
        with _SESSIONS_LOCK:
            if len(_SESSIONS) >= _MAX_SESSIONS:
                old = _SESSIONS_ORDER.pop(0)
                old_sess = _SESSIONS.pop(old, None)
                if old_sess:
                    try:
                        old_sess.close()
                    except Exception:
                        pass
            _SESSIONS[sid] = _ShellSession(command)
            _SESSIONS_ORDER.append(sid)
        sess = _SESSIONS[sid]
        out = sess.read(wait_seconds)
        status = "运行中" if sess.alive() else f"已退出 (code={sess.proc.returncode})"
        return f"[会话 {sid} 已打开，进程{status}]\n[启动输出]\n{out or '(无输出)'}"
    except Exception as e:
        return f"[shell_open 失败] {e}"


@register_tool(
    name="shell_send",
    description="向持久化 shell 会话发送输入（命令/payload/按键）。发送后自动等待并返回输出。",
    parameters={
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "shell_open 返回的会话 ID"},
            "text": {"type": "string", "description": "要发送的输入内容"},
            "press_enter": {"type": "boolean", "description": "是否在末尾追加回车（默认 true；发送原始 payload 时可设 false）"},
            "wait_seconds": {"type": "number", "description": "发送后等待输出的秒数（默认 2）"},
        },
        "required": ["session_id", "text"],
    },
)
def shell_send(session_id: str, text: str, press_enter: bool = True, wait_seconds: float = 2.0) -> str:
    try:
        sess = _get_session(session_id)
        sess.send(text + ("\n" if press_enter else ""))
        out = sess.read(wait_seconds)
        if not sess.alive():
            return f"[进程已退出 (code={sess.proc.returncode})]\n[输出]\n{out or '(无输出)'}\n会话已结束，如需重试请 shell_open 重新打开。"
        return f"[输出]\n{out or '(暂无输出，可用 shell_read 再等)'}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"[shell_send 失败] {e}"


@register_tool(
    name="shell_read",
    description="读取持久化 shell 会话的新增输出（不发送任何输入）。适合等待长时间运行的输出。",
    parameters={
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "shell_open 返回的会话 ID"},
            "wait_seconds": {"type": "number", "description": "最长等待秒数（默认 3，最多 30）"},
        },
        "required": ["session_id"],
    },
)
def shell_read(session_id: str, wait_seconds: float = 3.0) -> str:
    try:
        sess = _get_session(session_id)
        out = sess.read(min(wait_seconds, 30))
        status = "运行中" if sess.alive() else f"已退出 (code={sess.proc.returncode})"
        return f"[进程{status}]\n[输出]\n{out or '(暂无新输出)'}"
    except KeyError as e:
        return str(e)
    except Exception as e:
        return f"[shell_read 失败] {e}"


@register_tool(
    name="shell_close",
    description="关闭持久化 shell 会话（杀掉整个进程组）。解题收尾时清理用。",
    parameters={
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "要关闭的会话 ID"},
        },
        "required": ["session_id"],
    },
)
def shell_close(session_id: str) -> str:
    with _SESSIONS_LOCK:
        sess = _SESSIONS.pop(str(session_id), None)
        if str(session_id) in _SESSIONS_ORDER:
            _SESSIONS_ORDER.remove(str(session_id))
    if not sess:
        return f"[会话 {session_id} 不存在]"
    try:
        sess.close()
        return f"[会话 {session_id} 已关闭]"
    except Exception as e:
        return f"[关闭异常] {e}"


@register_tool(
    name="shell_list",
    description="列出所有存活的持久化 shell 会话。",
    parameters={"type": "object", "properties": {}},
)
def shell_list() -> str:
    if not _SESSIONS:
        return "[无活跃会话]"
    lines = []
    for sid in list(_SESSIONS_ORDER):
        sess = _SESSIONS.get(sid)
        if sess:
            status = "运行中" if sess.alive() else "已退出"
            lines.append(f"  {sid}: {status}")
    return "[活跃会话]\n" + "\n".join(lines)
