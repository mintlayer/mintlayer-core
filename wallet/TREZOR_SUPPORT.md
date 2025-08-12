## Using Mintlayer with Trezor

In order to use a Trezor device with Mintlayer, you'll have to:
- Flash the device with custom firmware provided by Mintlayer.
- Use one of the Mintlayer Core wallets - node-gui or wallet-cli. I.e. Trezor Suite won't be able to see your ML coins. Also, at this moment Mojito wallet doesn't support Trezor either, though there are plans to add the support in the future.

Note: Core wallets still require you to create a wallet file on your computer. In this case though only public keys will be kept in the wallet file (unless you explicitly add a standalone private key to it). Also note that you have to create a separate wallet file for each device/passphrase combination.

### Caveats

From the Trezor perspective, there are two types of firmware: a) the official one, signed by Trezor and perfectly safe to use; b) custom-built one, potentially unsafe to use.

Since Mintlayer is not officially supported by Trezor, the firmware we provide falls into the latter category. This has certain implications:
- When installing the firmware, the device will show the warning "UNSAFE, DO NOT USE!".
- When installing custom firmware over the official one, **the device will be wiped clean**. Make sure you have a backup of your seed phrase.
- When installing custom firmware over different custom firmware, the device will **not** be wiped clean. This makes it susceptible to the so-called "evil maid attack",
where the attacker has physical access to your device. It goes like this:
  * The "maid" temporarily steals your device and installs on it firmware that she has built herself; it looks identical to the previously installed firmware, but also logs the PIN and the passphrase entered by the user. Then she puts the device back.
  * You use the device.
  * She steals the device again and can now extract the logged PIN and passphrase. Moreover, knowing the PIN and being able to flash arbitrary firmware, she can now extract the seed phrase as well. So now she can either steal your coins right away or
  simply put the device back and wait until you accumulate more of them.

  So:
  * keep your device in a safe place;
  * preferably, use a dedicated device with a dedicated seed phrase and PIN specifically for Mintlayer;
- In order to install custom firmware on a Trezor Safe family device (e.g. Safe 3 or Safe 5), you have to [unlock the bootloader first](https://trezor.io/learn/security-privacy/how-trezor-keeps-you-safe/unlocking-the-bootloader-on-trezor-safe-devices);
this is an irreversible operation after which the device authenticity check will no longer work.
This means that every time you use Trezor Suite, you will be presented with a warning "Your device may have been compromised"
(unless you disable the authenticity check in the Trezor Suite's device settings).

### A note about versioning

Firmware built from the Mintlayer fork has two version numbers:
- A version number assigned by Trezor; this is the original release that we've based our release upon
  and this is what is shown to you on the device screen when you flash the firmware.
- An additional version number assigned by us, to which we refer as "Mintlayer firmware version";
  this is what our wallets display in their UI.

The table of correspondence between the two versions can be found in the [firmware repository](https://github.com/mintlayer/mintlayer-trezor-firmware/blob/mintlayer-master/README.md).

The Mintlayer firmware version determines the compatibility between the firmware and the Core wallets:

| Mintlayer Core version | Required Mintlayer firmware version |
| ---                    | ---                                 |
| 1.1.0                  | 1.x.x                               |

Note: if you've built Core wallets directly from `master` instead of using a specific release,
you'll probably won't be able to use a specific release for the firmware either.
Instead, you'll have to build it from `mintlayer-master`.

### Flashing pre-built firmware

If you are interested in a particular release, you may just go to [the firmware releases page](https://github.com/mintlayer/mintlayer-trezor-firmware/releases),
download the `.bin` file corresponding to your device model and install it via Trezor Suite:
- Inside Trezor Suite go to "Settings" -> "Device" -> "Danger area" -> "Install custom firmware" and click "Install".
- Follow the instructions that will appear on your screen.

Note:
- Trezor Safe 3 comes in two revisions, A and B, that look identical but require different firmware.\
  Determining the revision of your particular device is non-trivial, unfortunately:
  * If you have `trezorctl` installed, which is the Trezor command line tool, you may run `trezorctl get-features`[^1]
    (after having connected the device to the PC and having entered the PIN) and then look for the `internal_model` value
    in the output - 'T2B1' will mean you have revision A and 'T3B1' revision B.
  * In any case, the device won't allow you to install wrong firmware, so you may try the one for revision A
    and if that fails, try the one for revision B instead.
- Trezor Model One is not supported.

### Building the firmware from source

There are two options here:
- A more verbose approach using `Nix`, useful during development.
- A simpler approach using `Docker`; this results in reproducible builds and is used on our CI when creating releases.

In either case, you'll first need to clone the repository and checkout the required revision:
- If you want the latest version that is in development, checkout the `mintlayer-master` branch.
- If you want a particular release, checkout the tag corresponding to that release. The list of tags
  can be found [here](https://github.com/mintlayer/mintlayer-trezor-firmware/tags).

In the examples below we'll be assuming that you want the release 1.0.0, whose tag is `mintlayer-v1.0.0`.

#### Building the firmware using `Nix`

##### Get the source code

Clone the repository, `cd` into the directory and checkout the required revision:
```sh
git clone --recurse-submodules https://github.com/mintlayer/mintlayer-trezor-firmware
cd mintlayer-trezor-firmware
git checkout --recurse-submodules mintlayer-v1.0.0
```

##### Install `Nix`

On a Debian-based system you can do this via `sudo apt install nix-bin`.

Check that `Nix` works by running `nix-shell -p hello --run hello`

If you're getting the error `getting status of /nix/var/nix/daemon-socket/socket: Permission denied`
on your Linux machine, you may need to add the current user to the `nix-users` group:
```sh
sudo usermod -aG nix-users $USER
```
You'll also need to re-login after that.

If you're getting the error `file 'nixpkgs' was not found in the Nix search path`, add
the `nixpkgs` channel by running:
```sh
nix-channel --add https://nixos.org/channels/nixos-25.05 nixpkgs
nix-channel --update
```

Run `nix-shell -p hello --run hello` again. If everything is ok, it should print `Hello, world!`.

##### Install required Python dependencies via `Poetry`

```sh
nix-shell --run "poetry install"
```

##### Build the firmware

Run:

```sh
TREZOR_MODEL=T3T1 nix-shell --run "poetry run make -C core vendor build_firmware"
```

The value of the `TREZOR_MODEL` env variable determines the target device which the firmware will be built for.
The possible values are:
| TREZOR_MODEL value | Device model      |
| ---                | ---               |
| T2T1               | Model T           |
| T2B1               | Safe 3 revision A |
| T3B1               | Safe 3 revision B |
| T3T1               | Safe 5            |

So in the example above we're building it for Safe 5.

##### Flash the firmware

The file `core/build/firmware/firmware.bin` in the source directory will be the firmware that you've just built,
so you can go ahead and install it via Trezor Suite.

However you can also do it via the command line:

First you need to put your device into bootloader mode. To do so
- On Safe 3, hold the left button when connecting the USB cable.
- On Model T and Safe 5, swipe across the screen when connecting the USB cable.

After that the device will present you with an option to install firmware, select that option.

Now you can flash the firmware by running[^2]:
```sh
nix-shell --run "poetry run make -C core upload"
```

Note: after having installed the firmware you may use Mintlayer-specific commands of `trezorctl`. Run
```sh
nix-shell --run "poetry run trezorctl mintlayer --help"
```
to see what commands are available.

#### Building the firmware using `Docker`

##### Make sure `Docker` is installed and set up correctly

##### Get the source code

Clone the repository, `cd` into the directory and checkout the required revision:
```sh
git clone https://github.com/mintlayer/mintlayer-trezor-firmware
cd mintlayer-trezor-firmware
git checkout mintlayer-v1.0.0
```

Note that the `--recurse-submodules` parameter is not needed in this case. This is because the build script will
do the cloning again, so this initial clone is mainly to get the correct build script.

##### Build the firmware

Run:
```sh
PRODUCTION=0 ./build-docker.sh --models T3T1 --skip-bitcoinonly --targets firmware mintlayer-v1.0.0
```

Note:
- The value of the `--models` parameter is a comma-separated list of target device models.
  The possible values are the same as for the `TREZOR_MODEL` variable used in the previous section.
  E.g. here we will be building the firmware for Safe 5.
- The last argument is the repository revision from which the firmware will be built. Make sure you
  specify the same revision that you've used during the initial checkout. Also note that it has to
  be either a branch name or a tag, but not an arbitrary commit hash.
- `PRODUCTION=0` is needed to produce the "UNSAFE, DO NOT USE!" firmware with the "DEVEL" signature
  (as opposed to the "Trezor" firmware without a signature, which would be unusable).

The resulting binary will be `build/core-MODEL/firmware/firmware.bin`, where MODEL is the model identifier
that you've specified via the `--models` parameter
(i.e. in this particular example the path will be `build/core-T3T1/firmware/firmware.bin`).\
Install it via Trezor Suite.

[^1]: If you instead decide to build the firmware from source using the `Nix` approach,
you'll be able to run `trezorctl` directly from the source directory like this:
`nix-shell --run "poetry run trezorctl get-features"`.\
I.e. you won't have to install it separately in this case.

[^2]: instead of executing `nix-shell --run "poetry run YOUR_COMMAND"` every time,
you can enter the nix-shell by running `nix-shell`
and then inside the nix-shell enter poetry shell by running `poetry shell`.\
After this, you can run `YOUR_COMMAND` directly, e.g. `make -C core upload` or `trezorctl get-features`.