#!/bin/bash
set -eo pipefail


PROJECT_DIR="/opt/network_ids"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="network_ids.service"

MAIN_SERVICE="$PROJECT_DIR/src/ids/ids.py"
CLI_TOOL="$PROJECT_DIR/src/menu/menu.py"


systemctl disable "$SERVICE_NAME"
systemctl stop "$SERVICE_NAME"

rm -rf $PROJECT_DIR
rm $MAIN_SERVICE
