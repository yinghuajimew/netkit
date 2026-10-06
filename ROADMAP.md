# Haven Roadmap

## Completed

- [x] **Paste into terminal** — Paste button on keyboard toolbar and selection toolbar. Clipboard text sent as terminal input; selection cleared on paste.
- [x] **Import existing SSH keys** — Allow importing private keys (PEM/OpenSSH/PuTTY PPK format) from device storage, with passphrase support.
- [x] **Background connection notification** — Persistent Android notification while SSH sessions are active, so users know there's an open connection.
- [x] **OSC sequence support** — OSC 8 hyperlinks (clickable links in terminal output), OSC 9/777 notifications (toast foreground, Android notification background), OSC 7 working directory tracking.
- [x] **Bracket paste mode** — Wrap pasted text in `ESC[200~`/`ESC[201~` when DECSET 2004 is enabled, preventing accidental execution of multi-line paste.
- [x] **Highlighter-style text selection** — Long-press and drag to extend selection like a highlighter pen, with edge-scroll for selecting beyond the visible screen. Mutually exclusive gesture handling for tab swipe, scroll, and selection.
- [x] **Terminal rendering fix** — Post emulator writes to main thread to prevent concurrent native access during resize, fixing animation scroll corruption.
- [x] **Keyboard toolbar customization** — Configurable keyboard toolbar with JSON layout support: smaller keys, more keys per row, user-editable layout.
- [x] **Network discovery** — Automatic LAN discovery of SSH hosts via mDNS/broadcast, shown in the connection creation dialog.
- [x] **Port forwarding** — Local (`-L`) and remote (`-R`) SSH port forwarding with visual flow diagrams showing tunnel direction. Rules persist across sessions, auto-activate on connect, restore on reconnect. Live add/edit/remove on active sessions with port validation.
- [x] **ProxyJump / multi-hop tunneling** — `ssh -J` style jump hosts via JSch direct-tcpip channels. Jump host selector in connection editor, tree view of dependencies, cascade disconnect, and terminal access on the jump host with tmux/screen session flow.
- [x] **Backup & restore** — Encrypted export/import of SSH keys, connections, port forward rules, known hosts, and settings. AES-256-GCM with PBKDF2 key derivation, accessible from Settings.
- [x] **Custom session commands** — Override the default tmux/byobu/screen/zellij command template with a custom command using `{name}` placeholder for session name.
- [x] **Per-connection SSH options** — Freeform ssh_config-style options (Key Value per line) applied as JSch session config per connection profile.

## Near-term

- [ ] **Agent forwarding** — SSH agent forwarding for key-based authentication to hop hosts. Note: ProxyJump already solves multi-hop more securely (keys never leave the device). Agent forwarding is mainly useful for workflows like `git push` from a remote server using your local key.
- [ ] **Snippet/command library** — Save and recall frequently used commands.
- [ ] **Connection groups/folders** — Organize saved connections by project or environment.

## Longer-term

- [ ] **Mosh support** — UDP-based mobile shell for unreliable network connections.

## Haven 2.0 — Remote Desktop

Integrated graphical remote access over SSH, with no additional software required on the client side.

- [ ] **VNC viewer** — Embedded VNC client that connects through Haven's existing SSH port forwarding. Fork [vernacular-vnc](https://github.com/shinyhut/vernacular-vnc) (MIT, pure Java), replace AWT rendering with Android Bitmap/Canvas, render in Compose. User sets up a local forward to the remote VNC server and the viewer connects to localhost.
- [ ] **X11 forwarding** — Lightweight X11 server using [android-xserver](https://github.com/nwrkbiz/android-xserver) (MIT, pure Java, embeddable library). JSch already supports X11 channel forwarding. Suitable for individual X11 applications (xterm, plotting tools, simple GUIs) rather than full desktops.
- [ ] **RDP** — Windows remote desktop via [FreeRDP](https://github.com/FreeRDP/FreeRDP) (Apache 2.0). NDK/JNI integration, higher build complexity. Tunnelled over SSH for security.
