## Module `some_subsystem`

### Method `some_subsystem_name`

Parameters:
```
{}
```

Returns:
```
string
```


### Method `some_subsystem_add`

Parameters:
```
{
    "a": number,
    "b": number,
}
```

Returns:
```
number
```


### Subscription `some_subsystem_subscribe_squares`

Parameters:
```
{}
```

Produces:
```
number
```

Unsubscribe using `some_subsystem_unsubscribe_squares`.

### Method `some_subsystem_convoluted`

Parameters:
```
{
    "first": EITHER OF
         1) bool
         2) null,
    "second": [
        string,
        number,
        EITHER OF
             1) number
             2) null,
    ],
    "third": { string: [
        secs number,
        nanos number,
    ], .. },
}
```

Returns:
```
[ string, .. ]
```



