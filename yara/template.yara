rule rule_name
{
    meta:
        description = "Enter description"
        author = "Author of the rule"
        date = "todays date"
        reference = "word"
        hash = "hash of artifact being examined"
    strings:
        $s1 = "string"
        $h1 = "hex"
    condition:
        all of them
}