{
    "auth": {
        "username": string,
        "password": string OR null OR {
            "password_file": string,
            "key": string OR number OR null,
        },
    } OR {
        "cookie_file": string,
    } OR null,
    "command": {
        "launch_missiles": number,
    } OR "check_missile_stock",
}
