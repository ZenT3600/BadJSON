# BadJSON
> Weaponizing JSON Files
> (Made by: https://www.matteoleggio.it/)
---

### Description
BadJSON aims to help people hide messages or even full fledged files inside of unsuspectable JSON configuration files. The program uses the algorithm from the Enigma machine developed by the germans during WW2, as well as adds noise and uses a key to encrypt everything. Wether you simply want to share a secret message or you want to hide some personal files BadJSON is the tool for you.

### Installation
You can either download the source and use the python program directly or you can download a .EXE file from `/releases`. The source code supports all platforms, while the compiled release currently only supports Windows machines.

If you decided to download the source, make sure to install the needed modules for it to work.

### Usage
Example: Hide a PlainText file
```bash
python BadJSON.py --hide -i myFile.txt -o nothingHereSmile.json -k 123
```

Example: Hide a Binary file
```bash
python BadJSON.py --hide --binary -i myArchive.zip -o nothingHereSmile.json -k 123
```

Example: Reveal a BadJSON file contents and save it as PlainText
```bash
python BadJSON.py --show -i badJson.json -o secretRevealed.txt -k 123
```

Example: Reveal a BadJSON file contents and save it as Binary data
```bash
python BadJSON.py --show --binary -i badJson.json -o secretRevealed.zip -k 123
```
