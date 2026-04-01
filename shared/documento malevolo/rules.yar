rule sus_strings {
    strings:
        $forms = "Microsoft Forms 2.0 Form" ascii wide

        $entry_point = "Document_open"

        $obfu_name1 = "Pvncafg"
        $obfu_name2 = "Llzjsomymu"
        $obfu_name3 = "Qnrnsagenrr"

        $ps_part1 = "owershei"
        $ps_part2 = "ll -w hi"
        $ps_part3 = "dden -en cmu"

    condition:
        $forms and
        $entry_point and
        (
            $obfu_name1 or
            $obfu_name2 or
            $obfu_name3
        ) and (
            $ps_part1 and
            $ps_part2 and
            $ps_part3
        )

}