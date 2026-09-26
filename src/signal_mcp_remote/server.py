"""signal-mcp-remote -- a Signal account, served to remote MCP clients.

Wraps the installed signal-mcp package (https://github.com/googlarz/signal-mcp)
and serves its tools over streamable HTTP on the loopback interface, behind a
bearer secret, so one claude.ai custom connector reaches Signal from every
Claude surface (web, desktop, mobile) and from other remote MCP clients.
Configuration comes from environment variables; see config.example.env.

signal-mcp has to be corrected in several ways, and every correction lives
here and is applied at runtime; its installed files are never edited:

  * it starts, stops and SIGTERMs signal-cli itself -- neutralised;
  * 13 of its 79 tools are hidden and refused;
  * its file-path parameters accept any path -- confined to two folders;
  * its attachment copier reads the wrong field -- replaced;
  * its Desktop import is wrong on Linux three ways -- replaced;
  * a scheduled message that falls due while the daemon is down is marked
    failed for good -- replaced so it stays pending.

Nothing here prints or logs the secret, the Signal Desktop key, the keyring
password, message text, attachment contents, contact or group names, or a
phone number beyond its last four digits.

Run `signal-mcp-remote --help` for the subcommands.
"""

import argparse
import asyncio
import concurrent.futures
import contextlib
import hmac
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import httpx
import uvicorn

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolResult,
    CallToolRequestParams,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    ToolAnnotations,
)
from mcp_types import INVALID_PARAMS

from signal_mcp import client as sm_client
from signal_mcp import config as sm_config
from signal_mcp import server as sm_server
from signal_mcp import store as sm_store
from signal_mcp.client import SignalClient, SignalError
from signal_mcp.models import Attachment

__version__ = "1.0"

# ==========================================================================
# Constants. Tunables are read at call time, so the tests can shrink them.
# ==========================================================================

def _env(name, default=""):
    return os.environ.get(name, "").strip() or default


def _env_int(name, default):
    try:
        return int(_env(name, str(default)))
    except ValueError:
        raise SystemExit("%s must be a number" % name)


# Public host names (e.g. a Cloudflare Tunnel hostname) this server answers to,
# comma-separated. The first one is used by `check` for its live checks.
PUBLIC_HOSTS = tuple(h.strip().lower() for h in _env("SIGNAL_MCP_PUBLIC_HOSTS").split(",")
                     if h.strip())
HOST_NAME = PUBLIC_HOSTS[0] if PUBLIC_HOSTS else ""
PORT = _env_int("SIGNAL_MCP_PORT", 8766)
# Keep the bind address on the loopback interface and put a tunnel or reverse
# proxy in front; the server has no TLS of its own.
BIND = _env("SIGNAL_MCP_BIND", "127.0.0.1")

# signal-cli's HTTP daemon (signal-cli daemon --http HOST:PORT).
DAEMON_URL = _env("SIGNAL_CLI_DAEMON_URL", "http://127.0.0.1:7583").rstrip("/")
DAEMON_RPC = DAEMON_URL + "/api/v1/rpc"
DAEMON_EVENTS = DAEMON_URL + "/api/v1/events"
DAEMON_CHECK = DAEMON_URL + "/api/v1/check"

TOOL_TIMEOUT = 85          # Cloudflare cuts the request off at 100 seconds
DESKTOP_SOFT_TIMEOUT = 80  # then the import keeps going in the background
MAX_RESULT = 100000        # claude.ai truncates at about 150,000 characters
MAX_BODY = 1048576
EVENTS_READ_TIMEOUT = 60   # the daemon sends a keep-alive every 15 seconds
BACKOFF_MIN = 1.0
BACKOFF_MAX = 30.0
BACKOFF_RESET_AFTER = 60.0
SCHEDULE_INTERVAL = 60

RELEASES_LATEST = "https://github.com/AsamK/signal-cli/releases/latest"
SIGNAL_CLI = _env("SIGNAL_CLI_BIN", shutil.which("signal-cli") or "/usr/local/bin/signal-cli")

HOME = Path(os.path.expanduser("~"))
SECRET_PATH = Path(os.path.expanduser(
    _env("SIGNAL_MCP_SECRET_FILE", str(HOME / ".config" / "signal-mcp-remote" / "secret"))))
SECRET_DIR = SECRET_PATH.parent
STATE_DIR = Path(os.path.expanduser(
    _env("SIGNAL_MCP_STATE_DIR", str(HOME / ".local" / "state" / "signal-mcp-remote"))))
UPDATE_STATE = STATE_DIR / "update-check.json"
# The only folder (besides signal-mcp's attachment folder) files may be sent from.
OUTBOX_DIR = Path(os.path.expanduser(_env("SIGNAL_MCP_OUTBOX", str(HOME / "signal-outbox"))))
# systemd user units `check` expects to be active, comma-separated.
CHECK_UNITS = tuple(u.strip() for u in _env(
    "SIGNAL_MCP_CHECK_UNITS", "signal-cli-daemon,signal-mcp-remote").split(",") if u.strip())

# The 13 tools a chat model must not reach, with the reason in one line each.
HIDDEN = {
    "set_webhook": "would POST every incoming message to any URL",
    "get_webhook": "reveals that exfiltration URL",
    "receive_direct": "kills the daemon and takes over receiving",
    "upload_sticker_pack": "reads local files and publishes them",
    "trust_identity": "accepts a changed safety number, defeating the warning",
    "add_device": "links another device to the account",
    "remove_device": "unlinks a device, possibly this one",
    "update_device": "renames a linked device",
    "update_account": "changes account-wide registration settings",
    "set_pin": "sets the registration lock PIN",
    "remove_pin": "removes the registration lock PIN",
    "start_change_number": "begins moving the account to another number",
    "finish_change_number": "completes that move",
}

# Read-only means: nothing changes in Signal and nothing changes on disk,
# except that reading messages may mark them read in the local store.
# Derived by reading each tool's dispatch code, not from its name.
READ_ONLY = {
    "list_contacts", "find_contact", "list_groups", "list_conversations",
    "get_conversation", "search_messages", "get_unread",
    "get_profile", "get_user_status", "get_avatar", "get_sticker",
    "list_devices", "list_identities", "list_accounts", "list_sticker_packs",
    "list_attachments", "get_attachment",
    "get_own_number", "store_stats", "export_messages",
    "list_scheduled_messages",
}

DESTRUCTIVE = {
    "block_contact", "remove_contact",
    "delete_message", "delete_group_message", "admin_delete_message",
    "leave_group", "unpin_message", "terminate_poll",
    "clear_local_store", "delete_local_messages", "prune_store",
    "cancel_scheduled_message",
    "react_to_message", "update_group", "update_profile",
    "send_message_request_response",
}

# Tool arguments that name a local file (signal-mcp hands them to the daemon,
# which reads them), and so must be confined to the two allowed folders.
PATH_ARGS = {
    "send_attachment": ("paths", "path"),
    "send_group_attachment": ("paths", "path"),
    "send_note_to_self": ("attachments",),
    "update_profile": ("avatar_path",),
}


class Err(Exception):
    """A message for the operator plus an exit code. Never carries private data."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.message = message
        self.code = code


# ==========================================================================
# Output and logging
# ==========================================================================

def out(text=""):
    sys.stdout.write("%s\n" % text)


def note(text=""):
    sys.stderr.write("%s\n" % text)
    sys.stderr.flush()


def log_value(value):
    text = "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")
    if len(text) > 200:
        text = text[:200]
    if text == "" or " " in text or '"' in text or "=" in text:
        text = '"%s"' % text.replace('"', "'")
    return text


def log(fields):
    """One key=value line on stderr, for the journal. Never any argument."""
    parts = ["%s=%s" % (k, log_value(v)) for k, v in fields.items()
             if v is not None and v != ""]
    sys.stderr.write(" ".join(parts) + "\n")
    sys.stderr.flush()


def stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def last4(number):
    """The only part of a phone number that may ever be shown."""
    digits = re.sub(r"\D", "", number or "")
    return digits[-4:] if len(digits) >= 4 else "????"


# ==========================================================================
# Paths and permissions. The umask may be permissive, so every mode is set here.
# ==========================================================================

def attachments_source_dir():
    """Where signal-cli stores downloaded attachments. May not exist yet."""
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else HOME / ".local" / "share"
    return root / "signal-cli" / "attachments"


def chmod_if_exists(path, mode):
    try:
        if os.path.exists(path):
            os.chmod(path, mode)
    except OSError:
        pass


def fix_store_modes():
    """signal-mcp sets only messages.db; WAL and SHM inherit the umask."""
    chmod_if_exists(sm_store.DB_PATH.parent, 0o700)
    for suffix in ("", "-wal", "-shm"):
        chmod_if_exists(str(sm_store.DB_PATH) + suffix, 0o600)


def ensure_paths():
    """Create or repair every folder this build owns. Folders 700."""
    for folder in (SECRET_DIR, STATE_DIR, OUTBOX_DIR,
                   sm_config.ATTACHMENT_DIR, sm_store.DB_PATH.parent):
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(folder, 0o700)
        except OSError:
            pass


def create_secret_if_missing():
    SECRET_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRET_DIR, 0o700)
    if SECRET_PATH.exists():
        return
    tmp = str(SECRET_PATH) + ".tmp"
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "w") as fh:
            fh.write(secrets.token_urlsafe(32) + "\n")
        os.replace(tmp, SECRET_PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(SECRET_PATH, 0o600)


def read_secret():
    """Read the secret, refusing anything but mode 600 in a 700 folder."""
    if not SECRET_PATH.exists():
        raise Err("No secret yet. Start the server once: "
                  "signal-mcp-remote serve")
    folder_mode = stat.S_IMODE(os.stat(SECRET_DIR).st_mode)
    if folder_mode != 0o700:
        raise Err("%s must be mode 700, but it is %o. Fix that, then start "
                  "again." % (SECRET_DIR, folder_mode))
    mode = stat.S_IMODE(os.stat(SECRET_PATH).st_mode)
    if mode != 0o600:
        raise Err("%s must be mode 600, but it is %o. Fix that, then start "
                  "again." % (SECRET_PATH, mode))
    secret = SECRET_PATH.read_text().strip()
    if not secret:
        raise Err("The secret file is empty. Delete it and start the server "
                  "again to get a new one.")
    return secret


class SecretCache(object):
    """Holds the secret, re-reading it when the file's mtime or size change."""

    def __init__(self):
        self._secret = None
        self._key = None

    def get(self):
        try:
            info = os.stat(SECRET_PATH)
            key = (info.st_mtime_ns, info.st_size)
        except OSError:
            key = None
        if key is None:
            self._secret, self._key = None, None
            return None
        if key != self._key or self._secret is None:
            try:
                self._secret = read_secret()
                self._key = key
            except Err:
                self._secret, self._key = None, None
        return self._secret


# ==========================================================================
# Tool layer: hide 13 tools, confine file paths, cap results, time calls out
# ==========================================================================

_ORIG_CALL = sm_server.call_tool
ALL_TOOL_NAMES = frozenset(t.name for t in sm_server.TOOLS)

_LISTED = []          # the 66 annotated copies, built once at startup
_DESKTOP_LOCK = threading.Lock()
_DESKTOP_TASKS = set()
_SCHEDULE_LOCK = asyncio.Lock()


def tool_error(text):
    """A refusal or a failure, in signal-mcp's own shape."""
    return CallToolResult(
        content=[TextContent(type="text", text="Error: %s" % text)],
        is_error=True,
    )


def tool_ok(data):
    return CallToolResult(content=[TextContent(
        type="text", text=json.dumps(data, indent=2, default=str))])


def build_listed():
    """The 66 visible tools, as annotated copies.

    Copies, because signal_mcp._list_tools hands out the same module-level
    TOOLS list on every call -- and the 2026-07-28 entry calls tools/list
    again before every tool call that carries arguments.
    """
    listed = []
    for tool in sm_server.TOOLS:
        if tool.name in HIDDEN:
            continue
        copy = tool.model_copy(deep=True)
        fields = {
            "read_only_hint": tool.name in READ_ONLY,
            "destructive_hint": tool.name in DESTRUCTIVE,
        }
        if copy.annotations is not None:
            copy.annotations = copy.annotations.model_copy(update=fields)
        else:
            copy.annotations = ToolAnnotations(**fields)
        listed.append(copy)
    return listed


def assert_tools():
    """Fail loudly rather than serve a quietly wrong list."""
    total = len(sm_server.TOOLS)
    missing = sorted(set(HIDDEN) - ALL_TOOL_NAMES)
    if total != 79:
        raise Err("signal-mcp has %d tools, expected 79. Refusing to start."
                  % total)
    if missing:
        raise Err("these tools are meant to be hidden but do not exist: %s"
                  % ", ".join(missing))
    if len(_LISTED) != 66:
        raise Err("after hiding 13 tools, %d remain, expected 66."
                  % len(_LISTED))
    stray = sorted(READ_ONLY - ALL_TOOL_NAMES)
    if stray:
        raise Err("READ_ONLY names tools that do not exist: %s"
                  % ", ".join(stray))
    both = sorted(READ_ONLY & DESTRUCTIVE)
    if both:
        raise Err("these tools are both read-only and destructive: %s"
                  % ", ".join(both))


# ---- the file-path gate --------------------------------------------------

def allowed_roots():
    return (os.path.realpath(str(OUTBOX_DIR)),
            os.path.realpath(str(sm_config.ATTACHMENT_DIR)))


def path_refusal():
    return ("that file is not allowed. Only regular files inside %s or %s "
            "can be sent. Put the file in %s first."
            % (OUTBOX_DIR, sm_config.ATTACHMENT_DIR, OUTBOX_DIR))


def resolve_allowed(value):
    """Return the resolved path, or None when it must be refused."""
    if not isinstance(value, str) or not value:
        return None
    resolved = os.path.realpath(os.path.expanduser(value))
    roots = allowed_roots()
    inside = any(resolved == root or resolved.startswith(root + os.sep)
                 for root in roots)
    if not inside:
        return None
    if not os.path.isfile(resolved):
        return None
    return resolved


def gate_paths(name, args):
    """Check every file path before anything reaches signal-cli.

    Rewrites the arguments with resolved absolute paths. Returns a refusal
    message, or None when everything passed. Follows signal-mcp's own
    precedence: for the two attachment tools, `paths` wins over `path`.
    """
    keys = PATH_ARGS.get(name)
    if not keys:
        return None
    for key in keys:
        if key not in args or args[key] in (None, "", []):
            continue
        value = args[key]
        if isinstance(value, list):
            resolved = []
            for item in value:
                good = resolve_allowed(item)
                if good is None:
                    return path_refusal()
                resolved.append(good)
            args[key] = resolved
        else:
            good = resolve_allowed(value)
            if good is None:
                return path_refusal()
            args[key] = good
        # `paths` wins over `path`, exactly as signal-mcp resolves them, so
        # the ignored key is left alone.
        break
    return None


# ---- capping -------------------------------------------------------------

def cap_result(result):
    """Cut the result text at MAX_RESULT characters, in total."""
    limit = MAX_RESULT
    blocks = [c for c in result.content if isinstance(c, TextContent)]
    total = sum(len(c.text) for c in blocks)
    if total <= limit:
        return result
    kept = []
    used = 0
    for block in result.content:
        if not isinstance(block, TextContent):
            kept.append(block)
            continue
        if used >= limit:
            break
        room = limit - used
        if len(block.text) <= room:
            kept.append(block)
            used += len(block.text)
        else:
            kept.append(TextContent(type="text", text=block.text[:room]))
            used = limit
    kept.append(TextContent(type="text", text=(
        "\n\n[cut after %d of %d characters. Ask for less: a smaller limit, "
        "a since date, or a single recipient.]" % (limit, total))))
    return result.model_copy(update={"content": kept})


# ---- the Desktop runner --------------------------------------------------

def _desktop_work(name):
    """The actual import. A seam, so the tests can use a slow fake."""
    from signal_mcp import desktop as sm_desktop
    install_desktop_patches()
    if name == "import_desktop":
        return sm_desktop.import_from_desktop()
    return sm_desktop.sync_from_desktop()


def _desktop_worker(name):
    """Runs in a worker thread. Takes the lock itself, releases it itself."""
    if not _DESKTOP_LOCK.acquire(False):
        return ("busy", None)
    try:
        return ("ok", _desktop_work(name))
    except Exception as exc:
        return ("err", exc)
    finally:
        _DESKTOP_LOCK.release()
        try:
            fix_store_modes()
        except Exception:
            pass


async def _desktop_job(name):
    return await asyncio.to_thread(_desktop_worker, name)


async def run_desktop(name):
    """Start the import, and answer within DESKTOP_SOFT_TIMEOUT either way.

    The task is deliberately not tied to the request: the request ending must
    not cancel a half-finished import.
    """
    task = asyncio.create_task(_desktop_job(name))
    _DESKTOP_TASKS.add(task)
    task.add_done_callback(_DESKTOP_TASKS.discard)
    done, _pending = await asyncio.wait({task}, timeout=DESKTOP_SOFT_TIMEOUT)
    if task not in done:
        return tool_ok({
            "status": "still running",
            "note": "the import continues in the background; check "
                    "store_stats in a little while.",
        })
    kind, payload = task.result()
    if kind == "busy":
        return tool_error("already running")
    if kind == "err":
        return tool_error(exception_text(payload))
    return tool_ok(payload)


# ---- the wrapped handlers ------------------------------------------------

def exception_text(exc):
    """Short, generic text. Only our two user-facing classes say more."""
    from signal_mcp.desktop import DesktopImportError
    if isinstance(exc, (SignalError, DesktopImportError)):
        return str(exc)
    return exc.__class__.__name__


async def wrapped_list(ctx, params):
    """Never raises, and never rebuilds: the modern entry calls this before
    every tool call that carries arguments, and does not cache the answer."""
    global _LISTED
    try:
        if not _LISTED:
            _LISTED = build_listed()
    except Exception:
        pass  # keep the last good list
    return ListToolsResult(tools=list(_LISTED))


async def wrapped_call(ctx, params):
    name = params.name
    # Raised outside the catch-all, and the only protocol-level error here.
    # It has to live in tools/call: the modern entry's own tools/list lookup
    # is fail-open, so filtering the list hides nothing by itself.
    if name in HIDDEN or name not in ALL_TOOL_NAMES:
        log({"time": stamp(), "event": "tool", "tool": name,
             "outcome": "hidden"})
        raise MCPError(code=INVALID_PARAMS, message="Unknown tool: %s" % name)

    started = time.time()
    outcome = "ok"
    try:
        args = dict(params.arguments or {})
        refusal = gate_paths(name, args)
        if refusal is not None:
            outcome = "refused"
            return tool_error(refusal)
        call_params = params.model_copy(update={"arguments": args})

        if name in ("import_desktop", "sync_desktop"):
            result = await run_desktop(name)
        else:
            result = await asyncio.wait_for(
                _ORIG_CALL(ctx, call_params), TOOL_TIMEOUT)
        result = cap_result(result)
        if getattr(result, "is_error", False):
            outcome = "error"
        return result
    except MCPError:
        raise
    except asyncio.TimeoutError:
        outcome = "timeout"
        return tool_error("timed out after %d seconds" % TOOL_TIMEOUT)
    except Exception as exc:
        outcome = "error"
        return tool_error(exception_text(exc))
    finally:
        log({"time": stamp(), "event": "tool", "tool": name,
             "outcome": outcome,
             "ms": int((time.time() - started) * 1000)})


def install_tool_layer():
    global _LISTED
    _LISTED = build_listed()
    assert_tools()
    sm_server.app.add_request_handler(
        "tools/list", PaginatedRequestParams, wrapped_list)
    sm_server.app.add_request_handler(
        "tools/call", CallToolRequestParams, wrapped_call)


# ==========================================================================
# Daemon handling: this process never starts, stops or signals signal-cli
# ==========================================================================

async def _patched_ensure_daemon(self, force=False):
    if await self._daemon_alive():
        return
    raise SignalError("the signal-cli-daemon service is not running")


async def _patched_stop_daemon(self):
    return False


async def _patched_receive_direct(self, timeout=5):
    raise SignalError("receive_direct is not available here; incoming "
                      "messages are saved as they arrive")


async def _patched_prewarm(self):
    return None


async def _patched_watchdog(self):
    return None


def _patched_start_watchdog(self):
    return None


async def _patched_freshen_store(client):
    return None  # messages are saved live, so there is nothing to freshen


def install_daemon_patches():
    SignalClient.ensure_daemon = _patched_ensure_daemon
    SignalClient.stop_daemon = _patched_stop_daemon
    SignalClient.receive_direct = _patched_receive_direct
    SignalClient.prewarm = _patched_prewarm
    SignalClient.watchdog = _patched_watchdog
    SignalClient._start_watchdog = _patched_start_watchdog
    SignalClient._parse_attachments = _patched_parse_attachments
    SignalClient.process_scheduled_messages = _patched_process_scheduled
    sm_server._freshen_store = _patched_freshen_store


# ==========================================================================
# Saving messages: one events connection, ingested in order in one thread
# ==========================================================================

_SAVED_TOTAL = 0
_INGEST_POOL = None


def _patched_parse_attachments(self, data_message):
    """signal-mcp copies from attachment["filename"], which is the sender's
    own file name, so the copy always fails. The stored file is
    <attachments folder>/<id>, and the JSON id is exactly that file name."""
    results = []
    base = os.path.realpath(str(attachments_source_dir()))
    dest_dir = Path(sm_config.ATTACHMENT_DIR)
    absent = 0
    for att in data_message.get("attachments") or []:
        att_id = att.get("id") or ""
        local_path = None
        refused = False
        if att_id and ("/" in att_id or ".." in att_id):
            refused = True
        elif att_id:
            src = os.path.realpath(os.path.join(base, att_id))
            if not (src == base or src.startswith(base + os.sep)):
                refused = True
            elif os.path.isfile(src):
                try:
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    os.chmod(dest_dir, 0o700)
                    dest = str(dest_dir / att_id)
                    handle = os.open(
                        dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(handle, "wb") as target:
                        with open(src, "rb") as source:
                            shutil.copyfileobj(source, target)
                    os.chmod(dest, 0o600)
                    local_path = dest
                except OSError:
                    absent += 1
            else:
                absent += 1
        if refused:
            log({"time": stamp(), "event": "attachment", "refused": 1})
        results.append(Attachment(
            content_type=att.get("contentType", "application/octet-stream"),
            filename=att.get("filename", "") or "",
            local_path=local_path,
            size=att.get("size"),
            width=att.get("width"),
            height=att.get("height"),
            caption=att.get("caption"),
        ))
    if absent:
        log({"time": stamp(), "event": "attachment", "source_missing": absent})
    return results


def _ingest_sync(payload):
    """Exactly the loop body of SignalClient.receive_messages(). No new
    parsing: edits update a body, receipts are skipped, the rest is saved."""
    client = sm_server.get_client()
    data = payload.get("envelope", payload)
    edit_sender = data.get("source", "") or data.get("sourceNumber", "")
    data_message = data.get("dataMessage") or {}
    edit = data_message.get("editMessage")
    if not edit:
        sync_sent = (data.get("syncMessage") or {}).get("sentMessage") or {}
        edit = sync_sent.get("editMessage")
        if edit:
            edit_sender = client.account  # sync edits originated from us
    if edit:
        target_ts = edit.get("targetSentTimestamp")
        new_body = (edit.get("dataMessage") or {}).get("message", "") or ""
        if target_ts:
            sm_store.update_message_body(
                target_ts, new_body, edit_sender or None)
        return 0
    message = client._parse_envelope(payload)
    if message is None or message.receipt_type:
        return 0
    sm_store.save_message(message)
    return 1


def _ingest_one(payload):
    """One event, in the ingest thread. A bad event must not end the stream."""
    global _SAVED_TOTAL
    if "envelope" not in payload and "exception" in payload:
        exception = payload.get("exception") or {}
        log({"time": stamp(), "event": "events",
             "receive_exception": exception.get("type") or "unknown"})
        return 0
    try:
        saved = _ingest_sync(payload)
    except Exception as exc:
        log({"time": stamp(), "event": "ingest", "error": exc.__class__.__name__})
        return 0
    if saved:
        _SAVED_TOTAL += saved
        try:
            fix_store_modes()
        except Exception:
            pass
    return saved


def _sse_value(line, prefix):
    value = line[len(prefix):]
    if value.startswith(" "):
        value = value[1:]
    return value


async def events_task():
    """Hold one GET /api/v1/events open. That connection is also what makes
    the daemon receive at all, because --receive-mode on-connection leaves
    its own handler weak."""
    global _INGEST_POOL
    if _INGEST_POOL is None:
        _INGEST_POOL = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="ingest")
    loop = asyncio.get_running_loop()
    timeout = httpx.Timeout(connect=10.0, read=EVENTS_READ_TIMEOUT,
                            write=10.0, pool=10.0)
    backoff = BACKOFF_MIN
    async with httpx.AsyncClient(timeout=timeout) as http:
        while True:
            connected_at = None
            reason = None
            try:
                async with http.stream(
                        "GET", DAEMON_EVENTS,
                        headers={"Accept": "text/event-stream"}) as response:
                    response.raise_for_status()
                    connected_at = time.monotonic()
                    log({"time": stamp(), "event": "events",
                         "state": "connected"})
                    name = None
                    data_lines = []
                    async for line in response.aiter_lines():
                        line = line.rstrip("\r")
                        if line == "":
                            if name == "receive" and data_lines:
                                try:
                                    payload = json.loads("\n".join(data_lines))
                                except ValueError:
                                    payload = None
                                    log({"time": stamp(), "event": "events",
                                         "error": "bad_json"})
                                if payload is not None:
                                    saved = await loop.run_in_executor(
                                        _INGEST_POOL, _ingest_one, payload)
                                    if saved:
                                        log({"time": stamp(),
                                             "event": "ingest",
                                             "saved": saved,
                                             "total": _SAVED_TOTAL})
                            name = None
                            data_lines = []
                            continue
                        if line.startswith(":"):
                            continue  # keep-alive comment
                        if line.startswith("event:"):
                            name = _sse_value(line, "event:")
                        elif line.startswith("data:"):
                            data_lines.append(_sse_value(line, "data:"))
                    reason = "closed"
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                reason = exc.__class__.__name__
            log({"time": stamp(), "event": "events", "state": "lost",
                 "reason": reason})
            if connected_at is not None and (
                    time.monotonic() - connected_at) >= BACKOFF_RESET_AFTER:
                backoff = BACKOFF_MIN
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)


# ==========================================================================
# Scheduled messages
# ==========================================================================

async def _patched_process_scheduled(self):
    """signal-mcp marks a job failed on any exception, so a job that falls
    due while the daemon is down is lost for good. Here it stays pending.

    One lock for the whole round, so the timer and the run_scheduled_messages
    tool can never send the same job twice.
    """
    async with _SCHEDULE_LOCK:
        if not await self._daemon_alive():
            return []
        due = await asyncio.to_thread(
            sm_store.get_pending_scheduled, now=datetime.now())
        results = []
        for job in due:
            try:
                if job["group_id"]:
                    result = await self.send_group_message(
                        job["group_id"], job["message"])
                else:
                    result = await self.send_message(
                        job["recipient"], job["message"])
                await asyncio.to_thread(sm_store.mark_scheduled_sent, job["id"])
                results.append({"id": job["id"], "status": "sent",
                                "timestamp": result.timestamp})
            except Exception as exc:
                if not await self._daemon_alive():
                    # The daemon went away: leave this job pending and stop.
                    break
                await asyncio.to_thread(sm_store.mark_scheduled_failed,
                                        job["id"], exc.__class__.__name__)
                results.append({"id": job["id"], "status": "failed",
                                "error": exc.__class__.__name__})
        return results


async def scheduler_task():
    """signal-mcp's own watch loop never sends due jobs, so this does."""
    while True:
        await asyncio.sleep(SCHEDULE_INTERVAL)
        try:
            client = sm_server.get_client()
            results = await client.process_scheduled_messages()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log({"time": stamp(), "event": "scheduled",
                 "error": exc.__class__.__name__})
            continue
        if not results:
            continue
        sent = len([r for r in results if r.get("status") == "sent"])
        failed = len([r for r in results if r.get("status") == "failed"])
        try:
            waiting = len(await asyncio.to_thread(
                sm_store.list_scheduled_messages))
        except Exception:
            waiting = -1
        log({"time": stamp(), "event": "scheduled", "sent": sent,
             "failed": failed, "waiting": waiting})


# ==========================================================================
# The HTTP surface: one guard in front of the MCP session manager
# ==========================================================================

async def reply(send, status, payload=None, extra=None):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    headers = [(b"content-length", str(len(body)).encode("ascii"))]
    if payload is not None:
        headers.append((b"content-type", b"application/json"))
    for name, value in (extra or {}).items():
        headers.append((name.encode("ascii"), value.encode("ascii")))
    await send({"type": "http.response.start", "status": status,
                "headers": headers})
    await send({"type": "http.response.body", "body": body})


def fix_headers(scope, headers):
    """The MCP SDK 406s a POST with no Accept and 400s one with no
    Content-Type, before any of our code runs. Repair only those two."""
    changed = []
    accept = (headers.get("accept") or "").lower()
    wanted = ("application/json", "text/event-stream", "*/*")
    if not any(token in accept for token in wanted):
        changed.append(("accept", "application/json, text/event-stream"))
    if not headers.get("content-type"):
        changed.append(("content-type", "application/json"))
    if not changed:
        return
    names = set(name for name, _ in changed)
    raw = [(n, v) for n, v in scope["headers"]
           if n.decode("latin-1").lower() not in names]
    for name, value in changed:
        raw.append((name.encode("ascii"), value.encode("ascii")))
    scope["headers"] = raw


def build_guard(manager, port, cache):
    allowed_hosts = frozenset(PUBLIC_HOSTS + (
        "127.0.0.1:%d" % port, "localhost:%d" % port))

    async def guard(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        if scope["type"] != "http":
            return

        started = time.time()
        headers = {}
        for raw_name, raw_value in scope["headers"]:
            name = raw_name.decode("latin-1").lower()
            if name not in headers:
                headers[name] = raw_value.decode("latin-1")

        path = scope.get("path", "")
        method = scope.get("method", "")
        client_ip = headers.get("cf-connecting-ip") or ""
        if not client_ip:
            peer = scope.get("client") or ()
            client_ip = peer[0] if peer else "?"
        entry = {
            "time": stamp(),
            "client": client_ip[:200],
            "verb": method,
            "path": path,
            "origin_present": "yes" if "origin" in headers else "no",
            "ua": headers.get("user-agent") or "-",
            "accept": headers.get("accept") or "-",
            "mcp_version_header": headers.get("mcp-protocol-version") or "-",
        }

        async def finish(status):
            entry["status"] = status
            entry["ms"] = int((time.time() - started) * 1000)
            log(entry)

        host = (headers.get("host") or "").strip().lower()
        if host not in allowed_hosts:
            await reply(send, 421, {"error": "misdirected request"})
            return await finish(421)

        if path.rstrip("/") != "/mcp":
            await reply(send, 404, {"error": "not found"})
            return await finish(404)

        if method != "POST":
            await reply(send, 405, {"error": "method not allowed"},
                        {"Allow": "POST"})
            return await finish(405)

        secret = cache.get()
        offered = headers.get("authorization") or ""
        expected = "Bearer %s" % (secret or "")
        if not secret or not hmac.compare_digest(offered, expected):
            # No WWW-Authenticate and no resource_metadata: claude.ai must not
            # mistake this for an OAuth-protected server.
            await reply(send, 401, {"error": "unauthorized"})
            return await finish(401)

        fix_headers(scope, headers)
        seen = {"status": 0}

        async def watch(message):
            if message.get("type") == "http.response.start":
                seen["status"] = message.get("status", 0)
            await send(message)

        try:
            await manager.handle_request(scope, receive, watch)
        except Exception as exc:
            entry["error"] = exc.__class__.__name__
        return await finish(seen["status"] or 500)

    return guard


# ==========================================================================
# Signal Desktop: the Linux key, and a real SQLCipher 4 export
# ==========================================================================

_TEMP_DIRS = []
_ORIG_IMPORT = None


def _keyring_password():
    """The v11 password, from the default collection. Never unlocks anything."""
    from signal_mcp.desktop import DesktopImportError
    import secretstorage
    from secretstorage.exceptions import (
        ItemNotFoundException, LockedException, SecretServiceNotAvailableException)

    locked_note = ("the keyring is locked. Log in to the desktop so the "
                   "keyring is unlocked, then try again.")
    try:
        conn = secretstorage.dbus_init()
    except SecretServiceNotAvailableException:
        raise DesktopImportError(
            "the keyring is not reachable from here. " + locked_note)
    with contextlib.closing(conn):
        if not secretstorage.check_service_availability(conn):
            raise DesktopImportError("no keyring service is running. " + locked_note)
        try:
            collection = secretstorage.get_collection_by_alias(conn, "default")
        except ItemNotFoundException:
            raise DesktopImportError("there is no default keyring collection.")
        if collection.is_locked():
            raise DesktopImportError(locked_note)

        item = None
        try:
            for candidate in collection.search_items({"application": "Signal"}):
                if not candidate.is_locked():
                    item = candidate
                    break
        except Exception:
            item = None
        if item is None:
            # On some desktops the label is "Chromium Safe Storage", not
            # "Signal Safe Storage"; accept either.
            for candidate in collection.get_all_items():
                try:
                    if candidate.get_label() in (
                            "Signal Safe Storage", "Chromium Safe Storage"):
                        if not candidate.is_locked():
                            item = candidate
                            break
                except Exception:
                    continue
        if item is None:
            raise DesktopImportError(
                "could not find Signal's keyring item.")
        try:
            return item.get_secret()
        except LockedException:
            raise DesktopImportError(locked_note)


def _desktop_key_hex(encrypted_hex):
    """Chromium's Linux scheme. signal-mcp uses the macOS one and rejects v11."""
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from signal_mcp.desktop import DesktopImportError

    try:
        raw = bytes.fromhex(encrypted_hex)
    except (TypeError, ValueError):
        raise DesktopImportError("encryptedKey in config.json is not hex.")
    prefix = raw[:3]
    if prefix == b"v10":
        password = b"peanuts"
    elif prefix == b"v11":
        password = _keyring_password()
    else:
        raise DesktopImportError(
            "unknown encryptedKey format: the prefix is %r, but only v10 and "
            "v11 are understood." % prefix.decode("latin-1", "replace"))

    key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16, salt=b"saltysalt",
                     iterations=1).derive(password)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
    padded = decryptor.update(raw[3:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plain = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise DesktopImportError(
            "the Signal Desktop key did not decrypt. The keyring password "
            "does not match this database.")
    try:
        text = plain.decode("ascii")
    except UnicodeDecodeError:
        raise DesktopImportError(
            "the decrypted Signal Desktop key is not readable text.")
    if len(text) != 64 or re.fullmatch(r"[0-9a-fA-F]{64}", text) is None:
        raise DesktopImportError(
            "the decrypted Signal Desktop key is not 64 hex characters.")
    return text.lower()


def _desktop_decrypt_db(db_key_hex, db_path=None):
    """Export the encrypted database to a plain copy, in a private folder.

    signal-mcp shells out to a `sqlcipher` command, which Ubuntu 22.04 only
    ships at version 3; this uses the bundled SQLCipher 4 instead.
    """
    import sqlcipher3
    from signal_mcp import desktop as sm_desktop
    from signal_mcp.desktop import DesktopImportError

    source = Path(db_path) if db_path else sm_desktop.SIGNAL_DB
    folder = tempfile.mkdtemp(prefix="signal-mcp-remote-")
    os.chmod(folder, 0o700)
    _TEMP_DIRS.append(folder)

    copy = os.path.join(folder, "db.sqlite")
    shutil.copyfile(str(source), copy)
    for suffix in ("-wal", "-shm"):
        extra = str(source) + suffix
        if os.path.exists(extra):
            shutil.copyfile(extra, copy + suffix)

    profiles = (
        ("key-only", ()),
        ("signal-mcp", (
            "PRAGMA cipher_page_size = 4096",
            "PRAGMA kdf_iter = 1",
            "PRAGMA cipher_hmac_algorithm = HMAC_SHA512",
            "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512",
        )),
        ("compatibility-3", ("PRAGMA cipher_compatibility = 3",)),
    )
    opened = None
    for label, pragmas in profiles:
        conn = sqlcipher3.connect(copy)
        try:
            conn.execute('PRAGMA key = "x\'%s\'"' % db_key_hex)
            for pragma in pragmas:
                conn.execute(pragma)
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            opened = (label, conn)
            break
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
    if opened is None:
        raise DesktopImportError(
            "could not open the Signal Desktop database with any of the "
            "three settings profiles (key-only, signal-mcp, compatibility-3).")

    label, conn = opened
    log({"time": stamp(), "event": "desktop", "profile": label})
    plain = os.path.join(folder, "plain.sqlite")
    try:
        conn.execute("ATTACH DATABASE ? AS plaintext KEY ''", (plain,))
    except Exception:
        conn.execute("ATTACH DATABASE '%s' AS plaintext KEY ''" % plain)
    try:
        conn.execute("SELECT sqlcipher_export('plaintext')")
        conn.execute("DETACH DATABASE plaintext")
    finally:
        conn.close()
    chmod_if_exists(plain, 0o600)
    return Path(plain)


def _desktop_import_wrapper(*args, **kwargs):
    """Delete the whole temp folder afterwards, whatever happened.

    signal-mcp deletes only the plain file, which would leave a decrypted
    copy of every message behind.
    """
    mark = len(_TEMP_DIRS)
    try:
        return _ORIG_IMPORT(*args, **kwargs)
    finally:
        while len(_TEMP_DIRS) > mark:
            shutil.rmtree(_TEMP_DIRS.pop(), ignore_errors=True)


def install_desktop_patches():
    from signal_mcp import desktop as sm_desktop
    global _ORIG_IMPORT
    if getattr(sm_desktop, "_smh_patched", False):
        return
    _ORIG_IMPORT = sm_desktop.import_from_desktop
    sm_desktop._get_db_key_hex = _desktop_key_hex
    sm_desktop._decrypt_db_to_temp = _desktop_decrypt_db
    sm_desktop.import_from_desktop = _desktop_import_wrapper
    sm_desktop._smh_patched = True


# ==========================================================================
# serve
# ==========================================================================

async def warm_caches(client):
    """Not fatal: the daemon may still be starting, or be down for a while."""
    for _ in range(150):
        try:
            if await client._daemon_alive():
                await client._ensure_caches()
                log({"time": stamp(), "event": "caches", "state": "warm"})
                return
        except Exception:
            pass
        await asyncio.sleep(2)


def install_all(port):
    """Everything startup does before the socket opens."""
    ensure_paths()
    create_secret_if_missing()
    read_secret()  # refuses to start on a wrong mode
    sm_store.init_db()
    fix_store_modes()
    try:
        sm_config.check_signal_cli_version()
    except Exception as exc:
        log({"time": stamp(), "event": "startup",
             "warning": "signal-cli version check failed",
             "reason": exc.__class__.__name__})
    install_daemon_patches()
    install_tool_layer()
    client = SignalClient(daemon_url=DAEMON_RPC)
    sm_server._client = client
    return client


def make_manager():
    return StreamableHTTPSessionManager(
        app=sm_server.app,
        stateless=True,
        json_response=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=False),
        max_request_body_size=MAX_BODY,
    )


async def serve_async(port=None, sock=None):
    port = PORT if port is None else port
    client = install_all(port)
    manager = make_manager()
    guard = build_guard(manager, port, SecretCache())

    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(manager.run())
        events = asyncio.create_task(events_task())
        scheduler = asyncio.create_task(scheduler_task())
        warmer = asyncio.create_task(warm_caches(client))
        for task in (events, scheduler, warmer):
            stack.callback(task.cancel)
        config = uvicorn.Config(
            guard, host=BIND, port=port,
            access_log=False, server_header=False, date_header=False,
            proxy_headers=False, workers=1, log_level="warning",
            lifespan="off",
        )
        server = uvicorn.Server(config)
        log({"time": stamp(), "event": "listening",
             "address": "%s:%d" % (BIND, port), "tools": len(_LISTED),
             "version": __version__})
        if sock is not None:
            await server.serve(sockets=[sock])
        else:
            await server.serve()


def cmd_serve(args):
    try:
        asyncio.run(serve_async(args.port))
    except KeyboardInterrupt:
        pass
    return 0


# ==========================================================================
# show-header
# ==========================================================================

def cmd_show_header(args):
    if not sys.stdout.isatty():
        note("show-header prints a secret, so it only runs when stdout is a "
             "terminal. Run it yourself, in your own terminal.")
        return 2
    out("Bearer " + read_secret())
    return 0


# ==========================================================================
# import-desktop
# ==========================================================================

def cmd_import_desktop(args):
    ensure_paths()
    install_daemon_patches()
    install_desktop_patches()
    from signal_mcp import desktop as sm_desktop
    from signal_mcp.desktop import DesktopImportError

    started = time.time()
    try:
        result = sm_desktop.sync_from_desktop()
    except DesktopImportError as exc:
        note("import failed: %s" % exc)
        return 1
    finally:
        fix_store_modes()
    out("imported: %d" % result.get("imported", 0))
    out("skipped:  %d" % result.get("skipped", 0))
    out("total:    %d" % result.get("total", 0))
    out("seconds:  %.1f" % (time.time() - started))
    return 0


# ==========================================================================
# check-update
# ==========================================================================

def installed_signal_cli_version():
    result = subprocess.run([SIGNAL_CLI, "--version"], capture_output=True,
                            text=True, timeout=30)
    if result.returncode != 0:
        raise Err("signal-cli --version exited %d" % result.returncode)
    found = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout)
    if not found:
        raise Err("could not read the installed signal-cli version")
    return found.group(0)


def latest_signal_cli_version():
    response = httpx.get(RELEASES_LATEST, follow_redirects=False, timeout=20.0)
    location = response.headers.get("location") or ""
    found = re.search(r"/tag/v?(\d+\.\d+\.\d+)", location)
    if not found:
        raise Err("could not read the latest signal-cli version")
    return found.group(1)


def as_tuple(version):
    return tuple(int(part) for part in version.split("."))


def read_update_state():
    try:
        return json.loads(UPDATE_STATE.read_text())
    except Exception:
        return {}


def write_update_state(data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    tmp = str(UPDATE_STATE) + ".tmp"
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, UPDATE_STATE)
    os.chmod(UPDATE_STATE, 0o600)


UPDATE_TEXT = ("signal-cli %s is out (installed: %s). Update it soon: "
               "copies older than about three months stop working.")


def cmd_check_update(args):
    try:
        current = installed_signal_cli_version()
        latest = latest_signal_cli_version()
    except Exception as exc:
        log({"time": stamp(), "event": "check-update",
             "error": exc.__class__.__name__})
        return 0
    newer = as_tuple(latest) > as_tuple(current)
    if args.dry_run:
        out("installed %s, latest %s, newer: %s"
            % (current, latest, "yes" if newer else "no"))
        return 0
    if not newer:
        log({"time": stamp(), "event": "check-update", "newer": "no"})
        return 0
    state = read_update_state()
    if state.get("notified") == latest:
        log({"time": stamp(), "event": "check-update", "already_told": latest})
        return 0

    async def send():
        install_daemon_patches()
        client = SignalClient(daemon_url=DAEMON_RPC)
        sm_server._client = client
        await client.send_note_to_self(UPDATE_TEXT % (latest, current))

    try:
        asyncio.run(send())
    except Exception as exc:
        log({"time": stamp(), "event": "check-update",
             "error": exc.__class__.__name__})
        return 0
    state["notified"] = latest
    try:
        write_update_state(state)
    except OSError as exc:
        log({"time": stamp(), "event": "check-update",
             "error": exc.__class__.__name__})
    log({"time": stamp(), "event": "check-update", "told": latest})
    return 0


# ==========================================================================
# check
# ==========================================================================

MODERN = "2026-07-28"
DEFAULT_ACCEPT = "application/json, text/event-stream"


def rpc_body(method, params=None, msg_id=1):
    body = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        body["id"] = msg_id
    if params is not None:
        body["params"] = params
    return body


def modern_body(method, params=None, msg_id=1):
    params = dict(params or {})
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return rpc_body(method, params, msg_id)


def modern_headers(method, name=None):
    """All three must agree, or the SDK answers -32020 before we see it."""
    headers = {"MCP-Protocol-Version": MODERN, "Mcp-Method": method}
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


def local_request(port, body=None, host=None, path="/mcp", method="POST",
                  secret=None, extra=None, raw=None, accept=DEFAULT_ACCEPT,
                  content_type="application/json"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    payload = raw
    if payload is None and body is not None:
        payload = json.dumps(body).encode("utf-8")
    sent = {}
    if host is not None:
        sent["Host"] = host
    if secret:
        sent["Authorization"] = "Bearer " + secret
    if accept is not None:
        sent["Accept"] = accept
    if content_type is not None and payload is not None:
        sent["Content-Type"] = content_type
    sent.update(extra or {})
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in sent.items():
            conn.putheader(name, value)
        if payload is not None:
            conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders()
        if payload:
            conn.send(payload)
        response = conn.getresponse()
        text = response.read().decode("utf-8", "replace")
        status = response.status
    finally:
        conn.close()
    parsed = None
    if text:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    return status, parsed, text


def live_request(url, body=None, secret=None, extra=None, raw=None,
                 accept=DEFAULT_ACCEPT, method="POST"):
    headers = {}
    if secret:
        headers["Authorization"] = "Bearer " + secret
    if accept is not None:
        headers["Accept"] = accept
    content = raw
    if content is None and body is not None:
        content = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    headers.update(extra or {})
    response = httpx.request(method, url, headers=headers, content=content,
                             timeout=60.0, follow_redirects=False)
    parsed = None
    if response.content:
        try:
            parsed = response.json()
        except Exception:
            parsed = None
    return response.status_code, parsed, response.text


class Checker(object):
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            out("  ok    %s" % name)
        else:
            self.failed += 1
            out("  FAIL  %s%s" % (name, (" -- %s" % detail) if detail else ""))
        return ok

    def section(self, title):
        out("")
        out(title)


def error_code(body):
    if isinstance(body, dict):
        return (body.get("error") or {}).get("code")
    return None


def tools_of(body):
    if isinstance(body, dict):
        return ((body.get("result") or {}).get("tools")) or []
    return []


def tool_text(body):
    result = (body or {}).get("result") or {}
    blocks = result.get("content") or []
    return "\n".join(b.get("text", "") for b in blocks if isinstance(b, dict))


def run_protocol_checks(checker, send, kind):
    """The checks that are identical locally and through the tunnel."""
    status, body, _ = send(rpc_body("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "signal-mcp-remote check", "version": __version__},
    }))
    checker.check("%s: initialize succeeds" % kind,
                  status == 200 and isinstance(body, dict)
                  and "result" in body, "status %s" % status)

    status, _body, text = send(rpc_body("notifications/initialized",
                                        None, None))
    checker.check("%s: notifications/initialized -> 202" % kind,
                  status == 202 and text.strip() == "", "status %s" % status)

    status, body, _ = send(rpc_body("tools/list", {}))
    listed = tools_of(body)
    checker.check("%s: tools/list returns 66 tools" % kind,
                  len(listed) == 66, "got %d" % len(listed))
    names = set(t.get("name") for t in listed)
    checker.check("%s: none of the 13 hidden tools is listed" % kind,
                  not (names & set(HIDDEN)),
                  ", ".join(sorted(names & set(HIDDEN))))
    annotated = [t for t in listed
                 if isinstance(t.get("annotations"), dict)
                 and "readOnlyHint" in t["annotations"]]
    checker.check("%s: every listed tool has readOnlyHint" % kind,
                  len(annotated) == len(listed),
                  "%d of %d" % (len(annotated), len(listed)))
    flagged = set(t["name"] for t in listed
                  if (t.get("annotations") or {}).get("readOnlyHint"))
    checker.check("%s: readOnlyHint matches READ_ONLY" % kind,
                  flagged == READ_ONLY,
                  "%d flagged, %d expected" % (len(flagged), len(READ_ONLY)))

    status, body, _ = send(rpc_body("tools/call", {
        "name": "set_webhook", "arguments": {"url": "http://example.invalid"}}))
    checker.check("%s: a hidden tool gives -32602" % kind,
                  error_code(body) == -32602, "code %s" % error_code(body))

    status, body, _ = send(rpc_body("tools/call", {
        "name": "no_such_tool_at_all", "arguments": {}}))
    checker.check("%s: an unknown tool gives -32602" % kind,
                  error_code(body) == -32602, "code %s" % error_code(body))


def run_modern_checks(checker, send_modern, kind):
    status, body, _ = send_modern("server/discover", None, None)
    checker.check("%s 2026-07-28: server/discover succeeds" % kind,
                  status == 200 and isinstance(body, dict) and "result" in body,
                  "status %s" % status)

    status, body, _ = send_modern("tools/list", {}, None)
    listed = tools_of(body)
    checker.check("%s 2026-07-28: tools/list returns 66 tools" % kind,
                  len(listed) == 66, "got %d" % len(listed))

    status, body, _ = send_modern(
        "tools/call",
        {"name": "set_webhook", "arguments": {"url": "http://example.invalid"}},
        "set_webhook")
    checker.check("%s 2026-07-28: a hidden tool gives -32602" % kind,
                  error_code(body) == -32602, "code %s" % error_code(body))


def cmd_check(args):
    checker = Checker()
    port = args.port
    local_host = HOST_NAME or "127.0.0.1:%d" % port
    secret = None
    try:
        secret = read_secret()
    except Err as exc:
        out("cannot read the secret: %s" % exc.message)
        return 2

    def send_local(body, **kw):
        kw.setdefault("host", local_host)
        kw.setdefault("secret", secret)
        return local_request(port, body, **kw)

    def send_local_modern(method, params, name):
        return local_request(port, modern_body(method, params),
                             host=local_host, secret=secret,
                             extra=modern_headers(method, name))

    checker.section("Local, http://127.0.0.1:%d/mcp with Host: %s"
                    % (port, local_host))
    status, _b, _t = local_request(port, rpc_body("tools/list", {}),
                                   host=local_host, secret=None)
    checker.check("no secret -> 401", status == 401, "status %s" % status)

    status, _b, _t = local_request(port, rpc_body("tools/list", {}),
                                   host=local_host, secret="wrong-secret")
    checker.check("wrong secret -> 401", status == 401, "status %s" % status)

    status, _b, _t = local_request(port, rpc_body("tools/list", {}),
                                   host="elsewhere.example", secret=secret)
    checker.check("wrong Host -> 421", status == 421, "status %s" % status)

    status, _b, _t = local_request(port, None, host=local_host, secret=secret,
                                   method="GET")
    checker.check("GET /mcp -> 405", status == 405, "status %s" % status)

    status, _b, _t = local_request(
        port, rpc_body("tools/list", {}), host=local_host, secret=secret,
        path="/.well-known/oauth-protected-resource")
    checker.check("/.well-known/oauth-protected-resource -> 404",
                  status == 404, "status %s" % status)

    big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                      "params": {"pad": "x" * (2 * 1024 * 1024)}}).encode()
    status, _b, _t = local_request(port, None, host=local_host, secret=secret,
                                   raw=big)
    checker.check("a 2 MB body -> 413", status == 413, "status %s" % status)

    checker.section("Local, with the secret (handshake protocol)")
    run_protocol_checks(checker, send_local, "local")

    status, body, _ = send_local(rpc_body("tools/call", {
        "name": "send_attachment",
        "arguments": {"recipient": "+100",
                      "path": str(HOME / ".netrc")}}))
    text = tool_text(body)
    refused = ((body or {}).get("result") or {}).get("isError") is True
    checker.check("send_attachment with ~/.netrc is refused",
                  refused and "not allowed" in text, text[:60])

    status, body, _ = local_request(port, rpc_body("tools/list", {}),
                                    host=local_host, secret=secret,
                                    accept=None)
    checker.check("a POST with no Accept header still works",
                  status == 200 and len(tools_of(body)) == 66,
                  "status %s" % status)

    checker.section("Local, with the secret (2026-07-28 protocol)")
    run_modern_checks(checker, send_local_modern, "local")

    checker.section("Real read-only calls (counts only)")
    status, body, _ = send_local(rpc_body("tools/call", {
        "name": "get_own_number", "arguments": {}}))
    text = tool_text(body)
    try:
        own = json.loads(text)
        own_number = own if isinstance(own, str) else own.get("number", "")
    except Exception:
        own_number = text
    expected = ""
    try:
        data = json.loads(
            (HOME / ".local/share/signal-cli/data/accounts.json").read_text())
        for account in data.get("accounts", []):
            if str(account.get("number", "")).startswith("+"):
                expected = account["number"]
                break
    except Exception:
        expected = ""
    checker.check("get_own_number matches accounts.json (last 4: %s)"
                  % last4(expected),
                  bool(expected) and last4(own_number) == last4(expected),
                  "last 4 seen: %s" % last4(own_number))

    for tool, label in (("list_contacts", "contacts"),
                        ("list_groups", "groups")):
        status, body, _ = send_local(rpc_body("tools/call", {
            "name": tool, "arguments": {}}))
        try:
            items = json.loads(tool_text(body))
            count = len(items) if isinstance(items, list) else -1
        except Exception:
            count = -1
        checker.check("%s returns a list (%s: %d)" % (tool, label, count),
                      count >= 0, tool_text(body)[:60])

    status, body, _ = send_local(rpc_body("tools/call", {
        "name": "store_stats", "arguments": {}}))
    try:
        stats = json.loads(tool_text(body))
        ok = isinstance(stats, dict) and "total_messages" in stats
        detail = "total_messages %s, unread %s" % (
            stats.get("total_messages"), stats.get("unread_messages"))
    except Exception:
        ok, detail = False, tool_text(body)[:60]
    checker.check("store_stats works (%s)" % detail, ok)

    status, body, _ = send_local(rpc_body("tools/call", {
        "name": "list_scheduled_messages", "arguments": {}}))
    try:
        jobs = json.loads(tool_text(body))
        pending = len(jobs) if isinstance(jobs, list) else -1
    except Exception:
        pending = -1
    checker.check("pending scheduled jobs: %d" % pending, pending >= 0)

    # ---- live ----
    checker.section("Live, https://%s/mcp" % (HOST_NAME or "<no public host>"))
    resolves = bool(HOST_NAME)
    try:
        if resolves:
            socket.getaddrinfo(HOST_NAME, 443)
    except OSError:
        resolves = False
    if not HOST_NAME:
        out("  skipped -- SIGNAL_MCP_PUBLIC_HOSTS is not set.")
    elif not resolves:
        out("  skipped -- %s does not resolve yet. Add the Cloudflare route, "
            "then run this again." % HOST_NAME)
    else:
        url = "https://%s/mcp" % HOST_NAME
        try:
            status, _b, _t = live_request(url, rpc_body("tools/list", {}),
                                          secret=None)
        except Exception as exc:
            status = None
            out("  skipped -- %s" % exc.__class__.__name__)
        if status in (404, 502, 530, None):
            out("  skipped -- the route is not there yet (status %s)" % status)
        else:
            checker.check("live: no secret -> 401", status == 401,
                          "status %s" % status)

            def send_live(body, **kw):
                kw.pop("host", None)
                kw.setdefault("secret", secret)
                return live_request(url, body, **kw)

            def send_live_modern(method, params, name):
                return live_request(url, modern_body(method, params),
                                    secret=secret,
                                    extra=modern_headers(method, name))

            run_protocol_checks(checker, send_live, "live")
            run_modern_checks(checker, send_live_modern, "live")

    # ---- other ----
    checker.section("Other checks")
    listening = subprocess.run(["ss", "-ltn"], capture_output=True,
                               text=True).stdout
    # signal-cli's JVM HttpServer binds the IPv4-mapped form
    # [::ffff:127.0.0.1], which is still 127.0.0.1 and not a wildcard.
    loopback_forms = ("127.0.0.1", "::ffff:127.0.0.1", "::1")
    daemon_port = str(httpx.URL(DAEMON_URL).port or 80)
    for wanted in (daemon_port, str(port)):
        hosts = []
        for line in listening.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]
            if not local.endswith(":" + wanted):
                continue
            host = local[:-(len(wanted) + 1)]
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            hosts.append(host)
        ok = bool(hosts) and all(host in loopback_forms for host in hosts)
        checker.check("port %s listens on the loopback only" % wanted, ok,
                      ", ".join(hosts) if hosts else "nothing is listening")

    established = subprocess.run(
        ["ss", "-tn", "state", "established", "( dport = :%s )" % daemon_port],
        capture_output=True, text=True).stdout
    rows = [line for line in established.splitlines() if daemon_port in line]
    checker.check("one established connection to %s (the events stream)" % daemon_port,
                  len(rows) >= 1, "%d found" % len(rows))

    for unit in CHECK_UNITS:
        state = subprocess.run(["systemctl", "--user", "is-active", unit],
                               capture_output=True, text=True).stdout.strip()
        checker.check("%s is active" % unit, state == "active", state)
    state = subprocess.run(
        ["systemctl", "--user", "is-enabled", "signal-cli-update-check.timer"],
        capture_output=True, text=True).stdout.strip()
    checker.check("signal-cli-update-check.timer is enabled",
                  state == "enabled", state)

    for folder in (SECRET_DIR, STATE_DIR, OUTBOX_DIR,
                   Path(sm_config.ATTACHMENT_DIR), sm_store.DB_PATH.parent):
        try:
            mode = stat.S_IMODE(os.stat(folder).st_mode)
        except OSError:
            mode = None
        checker.check("%s is 700" % folder, mode == 0o700,
                      "%o" % mode if mode is not None else "missing")
    for path in [SECRET_PATH] + [Path(str(sm_store.DB_PATH) + s)
                                 for s in ("", "-wal", "-shm")]:
        if not os.path.exists(path):
            continue
        mode = stat.S_IMODE(os.stat(path).st_mode)
        checker.check("%s is 600" % path.name, mode == 0o600, "%o" % mode)

    leaked = 0
    key_shaped = 0
    for unit in CHECK_UNITS + ("signal-cli-update-check",):
        journal = subprocess.run(
            ["journalctl", "--user", "-u", unit, "--no-pager", "-n", "5000"],
            capture_output=True, text=True).stdout
        leaked += journal.count(secret)
        leaked += journal.count("Bearer ")
        key_shaped += len(re.findall(r"\b[0-9a-f]{64}\b", journal))
    checker.check("no secret or bearer header in the three journals",
                  leaked == 0, "%d match(es)" % leaked)
    checker.check("nothing key-shaped in the three journals",
                  key_shaped == 0, "%d match(es)" % key_shaped)

    try:
        current = installed_signal_cli_version()
        latest = latest_signal_cli_version()
        out("  info  installed %s, latest %s, newer: %s"
            % (current, latest,
               "yes" if as_tuple(latest) > as_tuple(current) else "no"))
    except Exception as exc:
        out("  info  check-update could not run (%s)" % exc.__class__.__name__)

    out("")
    out("%d ok, %d FAIL" % (checker.passed, checker.failed))
    return 1 if checker.failed else 0


# ==========================================================================
# entry point
# ==========================================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="signal-mcp-remote",
        description="Serve a Signal account to remote MCP clients over HTTP.")
    parser.add_argument("--version", action="version", version=__version__)
    subs = parser.add_subparsers(dest="command")

    serve = subs.add_parser("serve", help="serve MCP on 127.0.0.1")
    serve.add_argument("--port", type=int, default=PORT,
                       help="default: %d" % PORT)
    serve.set_defaults(func=cmd_serve)

    header = subs.add_parser(
        "show-header", help="print the Authorization line (terminal only)")
    header.set_defaults(func=cmd_show_header)

    importer = subs.add_parser(
        "import-desktop", help="import history from Signal Desktop")
    importer.set_defaults(func=cmd_import_desktop)

    updater = subs.add_parser(
        "check-update", help="send a Note to Self when signal-cli is old")
    updater.add_argument("--dry-run", action="store_true",
                         help="never send; just print the versions")
    updater.set_defaults(func=cmd_check_update)

    checks = subs.add_parser("check", help="check a running server")
    checks.add_argument("--port", type=int, default=PORT,
                        help="default: %d" % PORT)
    checks.set_defaults(func=cmd_check)
    return parser


def main(argv=None):
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


def run(argv=None):
    try:
        return main(argv)
    except Err as exc:
        note(exc.message)
        return exc.code
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        note("")
        return 130


if __name__ == "__main__":
    sys.exit(run())
