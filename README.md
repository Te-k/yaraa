# Yara Advanced - yaraa

## Features

* Keep a default list of Yara rules with `yaraa-config add`
* Quickly update yara rules in git repositores with `yaraa-config pull`
* Check files in archives :
    * zip
    * zip with password "infected" or "malware"
    * tar.gz
    * bzip2
    * Macros in files
* Check dex files in APKs

## Installation

For some technical reasons, you need to install [yara-python](https://github.com/VirusTotal/yara-python) manually form sources before install yaraa:

```
$ git clone --recursive https://github.com/VirusTotal/yara-python
$ cd yara-python
$ python setup.py build
$ sudo python setup.py install
```

Then you can install yaraa:

```
$ git clone https://github.com/Te-k/yaraa.git
$ cd yaraa
$ pip install .
```

## Usage

* Configure the default yara rules to be test : `yaraa-config add PATH`
* Update yara git folders : `yaraa-config pull`
* Check a folder, archive or file : `yaraa FILE`
* Check with a specific rule : `yaraa -r YARA_RULE FILE`

```
Advanced Yara checking

positional arguments:
  FILE                  File to be checked

optional arguments:
  -h, --help            show this help message and exit
  --rules RULES, -r RULES
                        Yara rules
  --verbose, -v         Verbose
```

As a library :
```
import yaraa

yaraa.lookup([YARA_RULE_PATH], FILE_PATH)
```

## Known Bugs

In some weird cases, yara-python does not compile rules the way [yara does](https://github.com/VirusTotal/yara-python/issues/112), it creates a `yara.SyntaxError` even if the Yara syntax is correct. There is no known workaround for now.

## Similar projects

* [yextend](https://github.com/BayshoreNetworks/yextend)

## License

This code is released under [MIT License](LICENSE).
