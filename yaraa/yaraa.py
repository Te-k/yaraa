import argparse
import os
import filetype
import yara
from zipfile import ZipFile


def analyze_final_file(name: str, data: bytes, rules: list) -> list:
    matches = []
    for rule in rules:
        res = rule.match(data=data)
        if len(res) > 0:
            matches += [x.rule for x in res]
    if len(matches):
        return [name, True, matches]
    else:
        return [name, False, []]


def analyze_file(path: str, rules: list) -> list:
    ttype = filetype.guess(path)
    if ttype:
        if ttype.mime == "application/zip":
            # APKs are ZIP files too, check if APK
            input_zip=ZipFile(path)
            all_files = input_zip.namelist()
            if 'classes.dex' in all_files and 'AndroidManifest.xml' in all_files:
                # TODO : sometimes several dex files
                data = input_zip.read('classes.dex')
                return analyze_final_file("{}:DEX".format(path), data, rules)
            else:
                # ZIP File, analyze all files one by one
                for f in input_zip.namelist():
                    data = input_zip.read(f)
                    return analyze_final_file("{}:{}".format(path, f), data, rules)
        else:
            with open(path, 'rb') as f:
                data = f.read()
                return analyze_final_file(path, data, rules)
    else:
        with open(path, 'rb') as f:
            data = f.read()
            return analyze_final_file(path, data, rules)
    return results


def lookup(rules: list, path: str) -> list:
    """
    Return an array of arrays, results under the format
        [filename, Detection, Rules]
        Detection is a boolean value about detection
    """
    crules = [yara.compile(r) for r in rules]
    # Test rules

    results = []

    if os.path.isdir(path):
        for r, d, f in os.walk(path):
            for file in f:
                results.append(analyze_file(os.path.join(r, file), crules))
    elif os.path.isfile(path):
        results.append(analyze_file(path, crules))
    return results
