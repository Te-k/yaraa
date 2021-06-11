import os
import yara
import io
import gzip
import tarfile
import bz2
import magic
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
    mime_type = magic.from_buffer(data, mime=True)
    results = []
    if mime_type:
        if mime_type == "application/java-archive":
            # APK
            fio = io.BytesIO(data)
            input_zip = ZipFile(fio)
            # FIXME : get all the dex files using androguard
            try:
                data = input_zip.read('classes.dex')
                results.append(analyze_final_file("{}:DEX".format(name), data, rules))
            except KeyError:
                pass
        elif mime_type == "application/zip":
            fio = io.BytesIO(data)
            input_zip = ZipFile(fio)
            all_files = input_zip.namelist()
            # ZIP File, analyze all files one by one
            try:
                for f in input_zip.namelist():
                    data = input_zip.read(f)
                    results += analyze_file("{}:{}".format(name, f), data, rules)
            except RuntimeError:
                # Password protected
                # Test with "infected"
                try:
                    for f in input_zip.namelist():
                        data = input_zip.read(f, pwd=b"infected")
                        results += analyze_file("{}:{}".format(name, f), data, rules)
                except RuntimeError:
                    # Try with "malware"
                    try:
                        for f in input_zip.namelist():
                            data = input_zip.read(f, pwd=b"malware")
                            results += analyze_file("{}:{}".format(name, f), data, rules)
                    except RuntimeError:
                        pass
        elif mime_type == "application/gzip":
            dd = gzip.decompress(data)
            results += analyze_file(name, dd, rules)
        elif mime_type == "application/x-tar":
            fio = io.BytesIO(data)
            tar = tarfile.open(fileobj=fio)
            for t in tar:
                # TODO : handle folders
                if t.isreg():
                    f = tar.extractfile(t)
                    data = f.read()
                    results += analyze_file("{}:{}".format(name, t.name), data, rules)
        elif mime_type == "application/x-bzip2":
            dd = bz2.decompress(data)
            results += analyze_file(name, dd, rules)
        elif mime_type == "application/msword":
            try:
                vbaparser = olevba.VBA_Parser(name, data=data)
                if vbaparser.detect_vba_macros():
                    macros = '\n'.join([a[3] for a in vbaparser.extract_macros()])
                    results.append(analyze_final_file('{}:macro'.format(name), macros, rules))
            except olevba.FileOpenError:
                # Not a doc file with macro
                pass
            # Also analyze the doc file
            results.append(analyze_final_file(name, data, rules))
        else:
            results.append(analyze_final_file(name, data, rules))
    else:
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

    if os.path.isfile(path):
        with open(path, 'rb') as f:
            return analyze_file(path, f.read(), crules)
    return []
