rule ROOTVERIFIER {
    strings:
        $s1 = "Welcome!" ascii

    condition:
        all of them
}

