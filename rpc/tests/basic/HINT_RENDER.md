{
    "auth": EITHER OF
         1) {
                "username": string,
                "password": EITHER OF
                     1) string
                     2) null
                     3) {
                            "password_file": string,
                            "key": EITHER OF
                                 1) string
                                 2) number
                                 3) null,
                        },
            }
         2) { "cookie_file": string }
         3) null,
    "command": EITHER OF
         1) { "launch_missiles": number }
         2) "check_missile_stock",
}
