import os

import yaraa

FOLDER = os.path.dirname(os.path.realpath(__file__)) + "/data/"


def test_basic_detection():
    """
    Test detection of a rule over a file
    """
    res = yaraa.lookup([FOLDER + "rule1.yar"], FOLDER + "data1.txt")
    assert (isinstance(res, list))
    assert (len(res) == 1)
    assert (res[0][1])
    assert (res[0][2][0] == "RULE1")


def test_apk_detection():
    """
    Test detection of a string in a DEX file in an APK
    """
    res = yaraa.lookup([FOLDER + "root.yar"], FOLDER + "com.abcdjdj.rootverifier_2.0.apk")
    assert (isinstance(res, list))
    assert (len(res) == 1)
    assert (res[0][1])
    assert (res[0][2][0] == "ROOTVERIFIER")


def test_zip_detection():
    """
    Test detection of a string in a file in a zip file
    """
    res = yaraa.lookup([FOLDER + "rule1.yar"], FOLDER + "data1.zip")
    assert (isinstance(res, list))
    assert (len(res) == 2)
    assert (res[0][1])
    assert (res[0][2][0] == "RULE1")
    assert (res[1][1] is False)


def test_apk_zip_detection():
    """
    Test detection of an apk in zip
    """
    res = yaraa.lookup([FOLDER + "root.yar"], FOLDER + "com.abcdjdj.rootverifier_2.0.apk.zip")
    assert (isinstance(res, list))
    assert (len(res) == 1)
    assert (res[0][1])
    assert (res[0][2][0] == "ROOTVERIFIER")


def test_tar_gz_detection():
    res = yaraa.lookup([FOLDER + "rule1.yar"], FOLDER + "data1.tar.gz")
    assert (isinstance(res, list))
    assert (len(res) == 1)
    assert (res[0][1])
    assert (res[0][2][0] == "RULE1")


def test_bzip2_detection():
    res = yaraa.lookup([FOLDER + "rule1.yar"], FOLDER + "data1.txt.bz2")
    assert (res.__class__ == list)
    assert (len(res) == 1)
    assert (res[0][1])
    assert (res[0][2][0] == "RULE1")


def test_doc_macro():
    res = yaraa.lookup([FOLDER + "macro.yar"], FOLDER + "maldoc.doc")
    assert (isinstance(res, list))
    assert (len(res) == 2)
    assert (res[0][2][0] == "MACRO")
