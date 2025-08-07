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
- When installing custom firmware over different custom firmware, the device will **not** be wiped clean. This makes it succeptible to the so-called "evil maid attack",
where the attacker has physical access to your device. It goes like this:
  * The "maid" temporarily steals your device and installs on it firmware that she has built herself; it looks identical to the previously installed firmware, but also logs the PIN and the passphrase entered by the user. Then she puts the device back.
  * You use the device.
  * She steals the device again and can now extract the logged PIN and passphrase. Moreover, knowing the PIN and being able to flash arbitrary firmware, she can now extract the seed phrase as well. So now she can either steal your coins right away or
  simply put the device back and wait until you accumulate more of them.

  So:
  * keep your device in a safe place;
  * preferably, use a dedicated device with a dedicated seed phrase and PIN specifically for Mintlayer;
- In order to install custom firmware on a Trezor Safe family device (e.g. Safe 3 or Safe 5), you have to [unlock the bootloader first](https://trezor.io/learn/security-privacy/how-trezor-keeps-you-safe/unlocking-the-bootloader-on-trezor-safe-devices);
this is an irreversible operation after which the device authenticity check will no longer work. This means that every time you use Trezor Suite, you will be presented with a warning "Your device may have been compromised" (unless you disable
the authenticity check in the Trezor Suite's device settings).

### Building and flashing the firmware

#### A note about versioning

Firmware built from the Mintlayer fork has two version numbers:
- A version number assigned by Trezor; this is the original release that we've based our release upon
  and this is what is shown to you on the device screen when you flash the firmware.
- An additional version number assigned by us, to which we refer as "Mintlayer firmware version".
  It is obtainable via `trezorctl mintlayer get-firmware-info` and it's what
  our wallets display in their UI.

The table of correspondence between the two versions can be found in the [firmware repository](https://github.com/mintlayer/mintlayer-trezor-firmware/blob/mintlayer-master/README.md).

The Mintlayer firmware version determines the compatibility between the firmware and the Core wallets:

| Mintlayer Core version | Required Mintlayer firmware version |
| ---                    | ---                                 |
| 1.1.0                  | 1.x.x                               |

Note: if you've built Core wallets directly from `master` instead of using a specific release,
you'll probably won't be able to use a specific release for the firmware either.
Instead, you'll have to build it from `mintlayer-master`.

#### How to build

##### Get the source code

Clone the repository and `cd` into it:
```sh
git clone --recurse-submodules https://github.com/mintlayer/mintlayer-trezor-firmware
cd mintlayer-trezor-firmware
```

Then checkout the required revision:
- If you want the latest version that is in development, checkout the `mintlayer-master` branch:
  ```sh
  git checkout --recurse-submodules mintlayer-master
  ```
- If you want a particular release, checkout the tag corresponding to that release. The list of tags
  can be found [here](https://github.com/mintlayer/mintlayer-trezor-firmware/tags).
  Assuming that you've chosen `mintlayer-v1.0.0`, run:
  ```sh
  git checkout --recurse-submodules mintlayer-v1.0.0
  ```

##### Install `Nix`

On a Debian-based system you can do this via `sudo apt install nix-bin`.

Check that `Nix` works by running `nix-shell -p hello --run hello`

If you're getting the error `getting status of /nix/var/nix/daemon-socket/socket: Permission denied`
on your Linux machine, you may need to add the current user to the `nix-users` group:
```sh
sudo usermod -aG nix-users your_username
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

Note:
- Trezor Safe 3 revision A and B look identical. To determine the revision of your particular device,
  first connect the device (which means, both connect it physically and enter the PIN) and then run:
  ```sh
  nix-shell --run "poetry run trezorctl get-features"
  ```
  Look for the `internal_model` value in the output.
- Trezor Model One is not supported.

##### Flash the firmware

First you need to put your device into bootloader mode. To do so
- On Safe 3, hold the left button when connecting the USB cable.
- On Model T and Safe 5, swipe across the screen when connecting the USB cable.

After that the device will present you with an option to install firmware, select that option.

Now you can flash the firmware by running:
```sh
nix-shell --run "poetry run make -C core upload"
```

Note: instead of executing `nix-shell --run "poetry run the_command"` every time, you can enter
the nix-shell by running `nix-shell`
and then inside the nix-shell enter poetry shell by running `poetry shell`.
After this, you can run the commands directly, e.g. `trezorctl get-features`.
