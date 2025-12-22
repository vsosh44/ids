#!/bin/bash
set -eo pipefail

sudo apt install python3.13 python3.13-venv git


PROJECT_DIR="/opt/network_ids"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="network_ids.service"

MAIN_SERVICE="$PROJECT_DIR/src/ids/ids.py"
MENU_PATH="$PROJECT_DIR/src/menu/menu.py"


sudo mkdir -p $PROJECT_DIR
sudo git clone https://github.com/nikita463/ids.git $PROJECT_DIR
sudo chown -R $USER:$USER $PROJECT_DIR


python3.13 -m venv $PROJECT_DIR/venv
$PROJECT_DIR/venv/bin/pip install -r $PROJECT_DIR/requirements.txt

mv $PROJECT_DIR/config-example.yaml $PROJECT_DIR/config.yaml


cat << EOF | sudo tee "$SERVICE_DIR/$SERVICE_NAME" >/dev/null
[Unit]
Description=Network IDS
After=network.target

[Service]
ExecStart=$PROJECT_DIR/venv/bin/python -m src.ids.ids
Restart=always
User=$USER
WorkingDirectory=$PROJECT_DIR

[Install]
WantedBy=multi-user.target
EOF


#sudo systemctl daemon-reload
#sudo systemctl enable "$SERVICE_NAME"
#sudo systemctl start "$SERVICE_NAME"
