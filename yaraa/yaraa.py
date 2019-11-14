import os
import filetype
import yara
import io
import gzip
import tarfile
import bz2
from zipfile import ZipFile
from oletools import olevba


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


def analyze_file(name: str, data: bytes, rules: list) -> list:
    ttype = filetype.guess(data)
    results = []
    if ttype:
        if ttype.mime == "application/zip":
            # APKs are ZIP files too, check if APK
            fio = io.BytesIO(data)
            input_zip = ZipFile(fio)
            all_files = input_zip.namelist()
            if 'classes.dex' in all_files and 'AndroidManifest.xml' in all_files:
                # TODO : sometimes several dex files
                data = input_zip.read('classes.dex')
                results.append(analyze_final_file("{}:DEX".format(name), data, rules))
            else:
                # ZIP File, analyze all files one by one
                for f in input_zip.namelist():
                    data = input_zip.read(f)
                    results += analyze_file("{}:{}".format(name, f), data, rules)
        elif ttype.mime == "application/gzip":
            dd = gzip.decompress(data)
            results += analyze_file(name, dd, rules)
        elif ttype.mime == "application/x-tar":
            fio = io.BytesIO(data)
            tar = tarfile.open(fileobj=fio)
            for t in tar:
                # TODO : handle folders
                if t.isreg():
                    f = tar.extractfile(t)
                    data = f.read()
                    results += analyze_file("{}:{}".format(name, t.name), data, rules)
        elif ttype.mime == "application/x-bzip2":
            dd = bz2.decompress(data)
            results += analyze_file(name, dd, rules)
        else:
            results.append(analyze_final_file(name, data, rules))
    else:
        # Doc files are not detected by filetype :(
        try:
            vbaparser = olevba.VBA_Parser(name, data=data)
            if vbaparser.detect_vba_macros():
                macros = '\n'.join([a[3] for a in vbaparser.extract_macros()])
                results.append(analyze_final_file('{}:macro'.format(name), macros, rules))
        except olevba.FileOpenError:
            # Not a doc file with macro
            pass
        results.append(analyze_final_file(name, data, rules))
    return results


def lookup(rules: list, path: str) -> list:
    """
    Return an array of arrays, results under the format
        [filename, Detection, Rules]
        Detection is a boolean value about detection
    """
    crules = [yara.compile(r) for r in rules]
    # TODO Test rules
    results = []

    if os.path.isdir(path):
        for r, d, f in os.walk(path):
            for file in f:
                with open(os.path.join(r, file), 'rb') as f:
                    results += analyze_file(os.path.join(r, file), f.read(), crules)
    elif os.path.isfile(path):
        with open(path, 'rb') as f:
            results += analyze_file(path, f.read(), crules)
    return results
