rule ROOTVERIFIER {
    strings:
        $s1 = "Welcome" ascii

    condition:
        uint16(0) == 0x6564 and all of them
}

