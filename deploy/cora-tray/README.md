# cora-tray

GNOME tray indicator for cora-sentinel. It shows the daemon's status and offers two emergency breakers per task.

| Icon | Meaning |
|---|---|
| green ✓ | all clear |
| amber … | the model is evaluating events |
| indigo 🔒 | containment active (or, in dry-run, what the model WOULD contain) |
| red ! | ALARM: an event was dropped uncontained, or an action failed. Stays red until the daemon restarts: read the decision log |
| grey ✕ | unreachable: no daemon, no permission, or no update for 6 s. Never shows a stale colour |

**Breakers only tighten.** *Sever network* (ISOLATE: nft drops the task's egress) and *Cap memory* (THROTTLE: memory held
at its current size, CPU 20%). Each asks for confirmation (Cancel is the default) and acts even when the daemon is in
dry-run: it is recorded in the decision log as `manual_operator_override` with your uid. The tray cannot undo either;
as root:

    sudo cora-firewall release TASK     # undo Sever
    sudo cora-cgroup reset TASK         # undo Cap

## Install (Ubuntu, GNOME)

    sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 gnome-shell-extension-appindicator
    sudo groupadd -f cora && sudo usermod -aG cora "$USER"          # then log out and back in
    # cora-sentinel: add to CORA_ARGS   --ui-socket /run/cora-sentinel/ui.sock --ui-group cora
    #                 (breakers also need --cgroup-root; Sever needs --nft)
    sudo systemctl restart cora-sentinel
    ln -s "$PWD/deploy/cora-tray/cora-tray" ~/.local/bin/cora-tray  # a symlink, so the icons are found
    cp deploy/cora-tray/cora-tray.desktop ~/.config/autostart/       # start at login

cora-tray runs on the **system** python3 (where `python3-gi` lives) and must be able to import `cora_sentinel`. If
cora-sentinel is only installed in a venv, edit the autostart entry to
`Exec=env PYTHONPATH=/path/to/cora-sentinel/src cora-tray`.

The same status in a terminal, no GTK needed: `python3 -m cora_sentinel.uiclient`.
