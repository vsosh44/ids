#!/bin/bash
set -eo pipefail


PROJECT_DIR="/opt/network_ids"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="network_ids.service"

MAIN_SERVICE="$PROJECT_DIR/src/ids/ids.py"
CLI_TOOL="$PROJECT_DIR/src/menu/menu.py"


sudo mkdir -p $PROJECT_DIR
sudo git clone https://github.com/nikita463/ids.git $PROJECT_DIR
sudo chown -R $USER:$USER $PROJECT_DIR


cat << EOF | sudo tee "$SERVICE_DIR/$SERVICE_NAME" >/dev/null
[Unit]
Description=Network IDS
After=network.target

[Service]
ExecStart=python3 -m $PROJECT_DIR.src.ids.ids
Restart=always
User=$USER
WorkingDirectory=$PROJECT_DIR

[Install]
WantedBy=multi-user.target
EOF


sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"
