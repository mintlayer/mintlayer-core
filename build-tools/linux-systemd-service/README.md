# Installing mintlayer daemon as a service in Linux (Debian and its derivatives)


## Security consideration, for both the safety of your coins and the security of your server

Note: If you're running mintlayer in your home or behind a consumer router, these instructions are not for you, unless you actively open your public ip address and all ports to the public.

Also, there are managed services that do this for you, but they're more expensive. We never had to use any of them, but it's up to you. One that comes to mind is Plesk. It's made to make server management easier. But it's not free.

1. NEVER run mintlayer software as root or a user that has access to root. It's preferable to create a separate user for this
2. NEVER keep all your server ports open. This is a huge security flaw that can endanger both your server and make stealing your coins easy. Mintlayer needs only port 13031 (testnet p2p) or 3031 (mainnet p2p). All other ports (maybe besides ssh) should be blocked by a firewall.
3. DO NOT allow public access to RPC (port 13030 for testnet, 3030 for mainnet). RPC basically gives full control and it's meant for the owner.
4. DO NOT bind RPC to 0.0.0.0 unless you know what you're doing. The correct way to reach your RPC is with an ssh tunnel, not by opening the RPC to the public.
5. After setting up your server, try to `telnet` to random ports on your server and make sure your firewall is blocking the connection. If the response is a timeout, then your firewall is working. If the response is "Connection Refused", that means your firewall is down.
6. Always ensure that your server is up-to-date with security patches of your system. On Debian, setup [Unattended Upgrades](https://wiki.debian.org/UnattendedUpgrades) to ensure that your system is consistently up-to-date, and make sure that updates are running every day by checking your system logs. Monitor it the first few days.
7. Use ssh public key authentication to login to your server. Using passwords is a bad idea, especially if it's not a long, random password generated by a random password generator; in which case: Why not just do the right thing and use public key for authentication?
8. Disable password authentication on ssh. There are tons of tutorials out there on how to harden ssh security, but disabling password authentication is a must nowadays.
9. If you want to keep your ssh port open to the public, install `fail2ban` and configure it to punish attempting to brute-force ssh access to your server.
10. Setup your server to send you emails when things go wrong. You can use sendmail, msmtp, or any other tool for that. Whatever works for you.

Make sure to test every attack you can think of, related to these points above after configuring your server. For example, after disabling ssh password authentication, attempt to login with a password and make sure it'll be rejected.

If you'd like to have a taste of how nightmarish server security is when it's open to the public, just keep watching the file `/var/log/auth.log` and see how many random ip addresses keep trying to brute-force access to your server through ssh with random usernames, keys and passwords. It's the age of botnets.

### Note on ignoring security

As Einstein said, "Two things are infinite: The universe and human stupidity; and I'm not sure about the universe".

Running a server is a responsibility that should not be taken lightly. Of course, we're not suggesting that you spend nights worrying about managing your server. If you follow the suggestions from above correctly, you'll be fine. However, if you think that running a server just means renting a VPS/root server for $20, then staking $100000 ML on it and think that's secure, it only means you're not ready and you should avoid running a server with a public ip address and a router that doesn't protect you from incoming connections.

We try to do the right thing, and we try to recommend correct security practices, but that's the end of what we can do. Mintlayer has done every security practice correctly and made it hard to do mistakes, but that's still not enough. If someone succeeds in gaining unauthorized access to your machine, there is nothing we can do to help there.

Consider checking out these stories:

- [The Billion Dollar Exploit: Collecting Validators Private Keys via Web2 Attacks](https://0d.dwalletlabs.com/the-billion-dollar-exploit-collecting-validators-private-keys-via-web2-attacks-4a385a5bb70d)
- [7,218 Ethers Stolen From Miner With RPC Port Open
](https://www.bokconsulting.com.au/blog/7218-ethers-stolen-from-miner-with-rpc-port-open/)

## How to create a system service that runs mintlayer daemon automatically for you

1. Choose whether you want to clone the source code, or download the release executable
2. Pick the appropriate service file from this directory for the node you need (testnet, mainnet, etc), one of the files ending with ".service". Let's say you picked [mintlayer-node-testnet.service](mintlayer-node-testnet.service)
3. Edit the following in the service file:

    A. The `user` to whatever user should run mintlayer daemon. NEVER use root or a user with root access.

    B. The `WorkingDirectory`; either point to the source code that you want to use to run, or the directory of the executable

    C. The `ExecStart`; If you want to run the executable manually, write the path of the executable of mintlayer daemon

4. Copy that file to the directory `/etc/systemd/system/` (you need root access for that). The file will end up being in: `/etc/systemd/system/mintlayer-node-testnet.service`
5. Make sure the file is owned by root by running: `chown root:root /etc/systemd/system/mintlayer-node-testnet.service`
5. Reload systemd services with: `sudo systemctl daemon-reload`
6. Enable the mintlayer daemon service with: `sudo systemctl enable mintlayer-node-testnet`
7. Start the service with: `sudo systemctl start mintlayer-node-testnet`
8. Now the service is continuously running. You can find the logs in `/var/log/`. To Ensure the service has started, run: `sudo journalctl -u mintlayer-node-testnet`, and you'll see at the end something like "Started mintlayer-node-testnet.service - Mintlayer Testnet Daemon"

## How to create a system service that runs the wallet and stakes

The same instructions from above, with little changes, apply to the wallet-rpc-daemon service. An example can be found here: [mintlayer-wallet-rpc-testnet.service](mintlayer-wallet-rpc-testnet.service)
