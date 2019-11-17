rule MACRO {
    strings:
        $a = "Attribute VB_Customizable" ascii
    condition:
        all of them
}
