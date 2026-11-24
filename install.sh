#!/data/data/com.termux/files/usr/bin/bash
# Installiert GrayLab in Termux. Aufruf: bash install.sh
set -e
pkg update -y && pkg install -y python git
mkdir -p "$PREFIX/bin"
printf '#!/data/data/com.termux/files/usr/bin/bash\ncd "%s"\nexec python graylab.py\n' "$(pwd)" > "$PREFIX/bin/graylab"
chmod +x "$PREFIX/bin/graylab"
echo "Fertig. Starte mit:  graylab   und öffne http://127.0.0.1:8080 in Chrome"