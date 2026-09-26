# signal-mcp-remote

**Remote (HTTP) MCP server for Signal Messenger.** It serves [signal-mcp](https://github.com/googlarz/signal-mcp) over streamable HTTP behind a bearer secret, so claude.ai custom connectors, the Claude mobile and desktop apps, Claude Code and other remote Model Context Protocol clients can read, search and send Signal messages through your own signal-cli daemon.

signal-mcp is a local (stdio) server. This wrapper installs it as a dependency, puts an HTTP front on it, and tightens it for remote use: it hides dangerous tools, confines file paths, keeps one live connection to the signal-cli daemon so every incoming message is saved, and fixes a few Linux problems at runtime. signal-mcp's own files are never edited.

## Features

- **66 Signal tools** from signal-mcp 1.36.0: messages, conversations, search, unread, groups, contacts, profiles, attachments, stickers, polls, reactions, pins, edits and deletes, scheduled messages, export, local store maintenance, Signal Desktop history import and sync.
  <details><summary>All 66 tool names</summary>

  add_sticker_pack, admin_delete_message, block_contact, cancel_scheduled_message, clear_local_store, create_group, create_poll, delete_group_message, delete_local_messages, delete_message, edit_message, export_messages, find_contact, get_attachment, get_avatar, get_conversation, get_own_number, get_profile, get_sticker, get_unread, get_user_status, import_desktop, join_group, leave_group, list_accounts, list_attachments, list_contacts, list_conversations, list_devices, list_groups, list_identities, list_scheduled_messages, list_sticker_packs, mark_as_unread, pin_message, prune_store, react_to_message, receive_messages, remove_contact, run_scheduled_messages, schedule_message, search_messages, send_attachment, send_contacts_sync, send_group_attachment, send_group_message, send_group_sticker, send_message, send_message_request_response, send_note_to_self, send_read_receipt, send_sticker, send_sync_request, set_expiration_timer, set_typing, store_stats, submit_rate_limit_challenge, sync_desktop, terminate_poll, unblock_contact, unpin_message, update_configuration, update_contact, update_group, update_profile, vote_poll
  </details>
- **13 tools hidden and refused**, because a chat model should not reach them: `set_webhook`, `get_webhook`, `receive_direct`, `upload_sticker_pack`, `trust_identity`, `add_device`, `remove_device`, `update_device`, `update_account`, `set_pin`, `remove_pin`, `start_change_number`, `finish_change_number`.
- **Tool annotations**: `readOnlyHint` on the 21 tools that change nothing, `destructiveHint` on the 16 that delete, block, leave or overwrite, so clients can auto-approve reads and ask before the rest.
- **File paths confined**: `send_attachment`, `send_group_attachment`, `send_note_to_self` and `update_profile` only accept regular files inside the outbox folder or signal-mcp's attachment folder.
- **Live saving**: one Server-Sent Events connection to the signal-cli daemon; every incoming message is stored as it arrives, with reconnect and backoff.
- **Scheduled messages** are sent every minute; a job that falls due while the daemon is down stays pending instead of failing.
- **Fixes applied at runtime to signal-mcp**: it never starts, stops or signals signal-cli (a systemd unit owns the daemon); incoming attachments are copied from the right file; Signal Desktop import works on Linux (v10/v11 key from the keyring, SQLCipher 4, the decrypted copy is always deleted).
- **Results capped** at 100,000 characters and **calls time out** after 85 seconds (Cloudflare ends requests at 100).
- `signal-mcp-remote check` runs a list of protocol, security and permission checks against a running server; `check-update` sends you a Note to Self when a newer signal-cli is out.

## Requirements

- Linux, Python 3.12 or newer
- [signal-cli](https://github.com/AsamK/signal-cli) with a registered or linked account, running as a daemon with its HTTP interface (`signal-cli -a <ACCOUNT> daemon --http 127.0.0.1:7583`); see [examples/signal-cli-daemon.service](examples/signal-cli-daemon.service)
- Optional, for Signal Desktop import on Linux: an unlocked desktop keyring, and the `desktop` extra
- Optional: `cloudflared`, to reach the server from claude.ai and mobile

## Install

```sh
git clone <this repository's URL> signal-mcp-remote
cd signal-mcp-remote
pipx install --python python3.12 .    # with Signal Desktop import: pipx install --python python3.12 '.[desktop]'
```

`--python` is only needed when your default `python3` is older than 3.12. This installs the `signal-mcp-remote` command, with signal-mcp 1.36.0 and the MCP SDK as pinned dependencies.

## Configure

All settings are environment variables and all are optional. See [config.example.env](config.example.env).

| Variable | Default | Meaning |
|---|---|---|
| `SIGNAL_MCP_BIND` | `127.0.0.1` | Address the server listens on. Keep it on the loopback interface |
| `SIGNAL_MCP_PORT` | `8766` | Port the server listens on (`--port` overrides it) |
| `SIGNAL_MCP_SECRET_FILE` | `~/.config/signal-mcp-remote/secret` | Bearer secret, created on first start (600, in a 700 folder) |
| `SIGNAL_MCP_PUBLIC_HOSTS` | none | Comma-separated public host names that may reach the server; the first is used by `check` |
| `SIGNAL_CLI_DAEMON_URL` | `http://127.0.0.1:7583` | The signal-cli daemon's HTTP address |
| `SIGNAL_CLI_BIN` | `signal-cli` on `PATH` | Used for version checks only |
| `SIGNAL_MCP_OUTBOX` | `~/signal-outbox` | The folder files may be sent from (besides signal-mcp's attachment folder) |
| `SIGNAL_MCP_STATE_DIR` | `~/.local/state/signal-mcp-remote` | Where `check-update` remembers what it reported |
| `SIGNAL_MCP_CHECK_UNITS` | `signal-cli-daemon,signal-mcp-remote` | systemd user units `check` expects to be active |

signal-mcp keeps its own message store in `~/.local/share/signal-mcp/` and saves attachments to `~/Downloads/signal-attachments/`.

## Run

```sh
signal-mcp-remote serve          # creates the secret on first start, serves on 127.0.0.1:8766
signal-mcp-remote show-header    # print "Bearer …" (only when stdout is a terminal)
signal-mcp-remote check          # check a running server
signal-mcp-remote import-desktop # import history from Signal Desktop
signal-mcp-remote check-update --dry-run
```

To rotate the secret, delete the secret file and restart the server; it writes a new one.

As systemd user services: copy the files in [examples/](examples) to `~/.config/systemd/user/`, fill in the placeholders, put your settings in `~/.config/signal-mcp-remote/env`, then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now signal-cli-daemon signal-mcp-remote
systemctl --user enable --now signal-cli-update-check.timer   # optional
journalctl --user -u signal-mcp-remote -f
```

## Connect to Claude

**claude.ai (web, desktop and mobile)**: Settings → Connectors → Add custom connector. URL `https://<your-public-host>/mcp`, and an `Authorization` header with the value from `signal-mcp-remote show-header`. claude.ai needs a public HTTPS URL; see the tunnel section below.

**Claude Code** on the same machine:

```sh
claude mcp add --transport http signal http://127.0.0.1:8766/mcp \
  --header "Authorization: Bearer $(cat ~/.config/signal-mcp-remote/secret)"
```

## Optional: expose over Cloudflare Tunnel

```sh
cloudflared tunnel create <TUNNEL-NAME>
cloudflared tunnel route dns <TUNNEL-NAME> <MCP-HOSTNAME>
```

Use [examples/cloudflared.yml](examples/cloudflared.yml) as the tunnel config, set `SIGNAL_MCP_PUBLIC_HOSTS=<MCP-HOSTNAME>`, and restart the service. The server itself still listens only on the loopback interface. Consider putting Cloudflare Access or a WAF rule in front as well: this server can read and send your messages.

## Security notes

- Every request needs `Authorization: Bearer <secret>`, compared in constant time; anything else gets `401`, with no OAuth metadata. The secret file must be mode 600 in a 700 folder or the server refuses to start. It is re-read when it changes.
- Requests whose `Host` is not `127.0.0.1:<port>`, `localhost:<port>` or a name in `SIGNAL_MCP_PUBLIC_HOSTS` get `421`. Only `POST /mcp` is served; request bodies are limited to 1 MB.
- Logs carry request metadata only (client address, path, status, timing, tool name and outcome), never the secret, message text, attachment contents, contact or group names, or a phone number beyond its last four digits.
- Hidden tools are refused at `tools/call`, not just left out of `tools/list`.
- Every folder the server creates is 700 and every file 600, whatever the umask.
- The daemon listens on the loopback interface too. Anyone who can reach it can use your account, so do not expose port 7583.

## Credits

- Written by Febin Micheal Antony.
- [signal-mcp](https://github.com/googlarz/signal-mcp) by Dawid Piaskowski (MIT) provides every Signal tool; this project depends on it and does not copy it.
- [signal-cli](https://github.com/AsamK/signal-cli) by AsamK (GPL-3.0) talks to Signal; this project only calls its daemon over HTTP and does not include it.
- The [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) and [Uvicorn](https://www.uvicorn.org/).

## License

[MIT](LICENSE), the same as signal-mcp.
