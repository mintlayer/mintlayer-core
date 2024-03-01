Assuming you use the systemd services of mintlayer, this is the logrotate file you can use. Make sure logrotate is installed. For Debian/Ubuntu:
```
sudo apt-get install logrotate
```
Then place it in the directory:
```
/etc/logrotate.d/
```

This will ensure that your logs don't grow infinitely large.
