# Yara Advanced - yaraa

Features :
* Keep a default list of Yara rules with `yaraa-config add`
* Quickly update yara rules in git repositores with `yaraa-config pull`
* Check files in archives - IN PROGRESS
    * zip : Done
    * tar.gz : Done
    * bzip2 : Done
    * Macros in files : TODO
* Check dex in android - Done
* If archive has password, test with infected - TODO
* Generate androguard json for APKs and check with androguard - TODO
    * https://github.com/Koodous/androguard-yara

## Known Bugs

In some weird cases, yara-python does not compile rules the way [yara does](https://github.com/VirusTotal/yara-python/issues/112), it creates a `yara.SyntaxError` even if the Yara syntax is correct. There is no known workaround for now.

## You may also be interested in

* [yextend](https://github.com/BayshoreNetworks/yextend)

## License

This code is released under [MIT License](LICENSE).
