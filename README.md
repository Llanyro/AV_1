# AV_1

## System Requirements
```
OS: Any (Tested in Ubuntu 20.04.2 LTS)
Software: Python 3
Storage: 550 mb
```

## Set-Up
```
sudo apt install python3
pip3 install -r requirements.txt or python3 -m pip3 install -r requirements.txt
```

## Usage
### Analize file or files in directory
```
python3 main.py -f '/path/file'
python3 main.py -d '/path'
```
### Select scanners
Scanners used are:
* Virustotal: Visutotal api
* MagicSimpleAnalysis: Analysis of magic numbers and file extensions
* AI_1: Static analysis with Logistic Regression model

#### Only local scanners
```
python3 main.py -f '/path/file' -s local
```
#### All scanners
```
python3 main.py -f '/path/file' -s all
```
#### Specific scanner
```
python3 main.py -f '/path/file' -s ai_1
python3 main.py -f '/path/file' -s virustotal
python3 main.py -f '/path/file' -s magic_ext
```
### Export result as plain text or json
```
python3 main.py -f '/path/file' -o plain
python3 main.py -f '/path/file' -o json
```
### Analize file and don't save result in database
```
python3 main.py -s local -f '/path/file' -n
```
### Show capabilities of file or files in directory
Uses binary [capa](https://github.com/fireeye/capa)
```
python3 main.py -f '/path/file' -c
python3 main.py -d '/path' -c
```
### Rescan
Ignore data in database about the file to scan and use scanners again as new file
```
python3 main.py -f '/path/file' -r
```




