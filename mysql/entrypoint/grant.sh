#!/bin/sh
set -eu

MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root -e "GRANT PROCESS ON *.* TO '${MYSQL_USER}'@'%';"
