# GrayLab – Security Toolkit (Termux / Android)

Dashboard, Hash-Tool (MD5, SHA-1/256/384/512, SHA3-256, BLAKE2b), Passwort-Lab, Encoder/Decoder und TCP-Port-Scanner.
Läuft lokal auf dem Handy: Python-Backend (nur Standardbibliothek) + Web-UI im Browser.

## Installation in Termux

```bash
pkg update -y && pkg install -y python git
git clone https://github.com/DEIN_USER/graylab.git
cd graylab
bash install.sh     # optional: legt den Befehl "graylab" an
python graylab.py   # oder: graylab
```

Dann in Chrome öffnen: http://127.0.0.1:8080

Update: `cd graylab && git pull`

## Hinweise
- Der Server lauscht nur auf 127.0.0.1 (nicht aus dem Netzwerk erreichbar).
- Port-Scanner nur für eigene Geräte/Netze oder mit Erlaubnis nutzen.
- Der Netzwerk-Monitor der Desktop-Version fehlt: Android sperrt die Verbindungsliste für normale Apps.
- `index.html` funktioniert auch allein (ohne Server), dann ohne Scanner und ohne SHA3/BLAKE2b.