rule RULE1 {
    strings:
        $s1 = "DETECTDETECT" ascii

    condition:
        all of them
}

