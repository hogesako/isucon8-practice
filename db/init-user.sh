#!/bin/bash

cat <<'EOF' | mysql -uroot
CREATE USER 'isucon'@'%' IDENTIFIED BY 'isucon!9910ISUCON';
GRANT ALL ON torb.* TO 'isucon'@'%';
CREATE USER 'isucon'@'localhost' IDENTIFIED BY 'isucon!9910ISUCON';
GRANT ALL ON torb.* TO 'isucon'@'localhost';
EOF
