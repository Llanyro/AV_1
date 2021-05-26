# AV_1

## System Requirements
```
OS: Any (Tested in Ubuntu 20.04.2 LTS)
Software: Python 3
Storage: 550 mb
```

## Set-Up
```
git clone https://github.com/Llanyro/AV_1
cd AV_1
git submodule init
git submodule update
sudo apt install python3
pip3 install -r requirements.txt or python3 -m pip3 install -r requirements.txt
```

## Usage
```
$ python3 main.py -h
usage: main.py [-h] [-f FILE] [-d DIR] [-c] [-s SCANNERS] [-r] [-o OUTPUT] [-n]

Analizador de binarios maliciosos

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Fichero a escanear
  -d DIR, --dir DIR     Directorio a escanear
  -c, --capa            Muestra las capabilities del escaneo
  -s SCANNERS, --scanners SCANNERS
                        Scanners a usar(ai_1, virustotal, magic_ext, local, all)
  -r, --re_scan         Reinicia el scan ignorando el resultado anterior del mismo binario(Si ya existia)
  -o OUTPUT, --output OUTPUT
                        Genera un fichero output que contiene el resultado del analisis en (json o plain)
  -n, --no_save         Fuerza a no guardar los resultados en la base de datos local
```
### Analize file or files in directory
```
python3 main.py -f '/path/file'
python3 main.py -d '/path'
```
### Select scanners
Scanners used are:
* Virustotal: Virustotal api
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




