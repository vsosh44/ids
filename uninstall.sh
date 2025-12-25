#!/bin/bash

PROJECT_DIR="/opt/network_ids"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="network_ids.service"

MAIN_SERVICE="$PROJECT_DIR/src/ids/ids.py"
MENU_PATH="$PROJECT_DIR/src/menu/menu.py"


systemctl disable "$SERVICE_NAME"
systemctl stop "$SERVICE_NAME"

rm -rf $PROJECT_DIR
rm $SERVICE_DIR/$SERVICE_NAME
