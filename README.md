# Custota

<img src="app/images/icon.svg" alt="app icon" width="72" />

![latest release badge](https://img.shields.io/github/v/release/chenxiaolong/Custota?sort=semver)
![license badge](https://img.shields.io/github/license/chenxiaolong/Custota)

Custota is an app for installing Android A/B OTA updates from a custom OTA server. When paired with [avbroot](https://github.com/chenxiaolong/avbroot), it can be used to seamlessly install OTAs signed by a custom key.

Custota is installed via a Magisk/KernelSU module so that it can run as a system app.

<img src="app/images/light.png" alt="light mode screenshot" width="200" /> <img src="app/images/dark.png" alt="dark mode screenshot" width="200" />

## Features

* Supports Android 13 and newer
* Supports pausing, resuming, and cancelling updates
* Supports skipping optional post-install scripts to speed up updates
* Never communicates with any server besides the configured OTA server
* OTA updates safely continue running even if the app crashes or is uninstalled during the operation

## Limitations

* The device must support A/B updates.
  * This notably excludes all Samsung devices.
* Incremental updates are not supported.
  * It would take minimal work to add support, but there's currently no tooling to generate an incremental OTA from two full OTAs.
* Pre-downloading an update to install later is not supported.
  * Custota runs `update_engine` in streaming mode, which downloads and installs OTAs at the same time.
* The stock OS' Settings app on Pixel devices always launches the builtin OTA updater.
  * These shortcuts in the Settings app are loaded from GmsCore (part of Google Play Services) via a mechanism called "settings slices" and cannot be overridden. Apps that launch the OTA updater via the standard `android.settings.SYSTEM_UPDATE_SETTINGS` intent will show a prompt to pick between Custota or the builtin OTA updater.

## Usage

1. Follow the instructions in the [OTA server](#ota-server) section to set up a webserver and generate the metadata files for the OTA zips.

2. If you're installing OTA updates signed with a custom key, follow the instructions in the [Custom Verification Key](#custom-verification-key) section.

3. Download the latest version from the [releases page](https://github.com/chenxiaolong/Custota/releases). To verify the digital signature, see the [verifying digital signatures](#verifying-digital-signatures) section.

4. Install the Custota module in Magisk/KernelSU.

5. Reboot and open Custota.

6. Set the OTA server URL to point to your OTA server.

7. That's it!

## OTA server

Custota only requires a basic webserver capable of serving static files and supporting the HTTP `Range` header. Any standard webserver, like Apache, Nginx, or Caddy, will do the trick. For testing, Caddy is very useful because it can serve files from a directory without setting up any config files:

```bash
caddy file-server -access-log -listen :8080
```

Custota looks for update metadata at `<url>/<device codename>.json`. The metadata JSON file looks like this:

```jsonc
{
    "full": {
        // The location can be a relative path or a full URL.
        "location": "path/to/ota.zip",

        // The values of the `metadata` entry from `ota-property-files`
        // inside the OTA's META-INF/com/android/metadata file.
        "metadata_offset": 2343312763,
        "metadata_size": 646
    }
}
```

To generate the metadata JSON file, run the following command from the directory containing the OTA zip:

```bash
python3 generate_metadata.py path/to/ota.zip
```

By default, the script will create `<device codename>.json` in the current directory. `-o <path>` can be used to specify a different path. The script will warn if the filename does not match the device codename.

The `location` field is set to the OTA zip path provided on the command line. If the path on the server is different, use `-l <path>` to set `location` appropriately. `-l <URL>` can also be used if the zip files will be hosted on a different domain.

### HTTPS

Custota respects Android's user trust store, but `update_engine` does not. In fact, it doesn't even use the normal system trust store and instead, has its own at `/system/etc/security/cacerts_google`. This limited trust store only contains a few CA certificates, notably excluding Let's Encrypt.

Custota's module will automatically override `update_engine`'s trust store to match the normal system trust store _and_ user trust store.

To use a self-signed certificate or a custom CA certificate:

1. Import the certificate into the user trust store in Android's Settings app.

2. Flash (or reflash) Custota.

If the CA certificate ever needs to be updated again, just repeat these steps.

## Custom verification key

Android's `update_engine` verifies OTA signatures against certificates contained within `/system/etc/security/otacerts.zip`. To install custom signed OTAs, this zip file needs to be replaced with one that contains the custom signing certificate.

To do so, run:

```bash
python3 customotacerts/build.py -c /path/to/certificate.crt
```

This creates a Magisk/KernelSU module that overrides `otacerts.zip`. After flashing both this module and Custota, to confirm that it works, just open the Custota app. The app lists the certificates that are currently active on the system.

## Permissions

* `ACCESS_CACHE_FILESYSTEM` (**automatically granted by system app permissions**)
  * Needed to store temporary OTA files.
* `FOREGROUND_SERVICE` (**automatically granted at install time**)
  * Needed to run the OTA update service in the background.
* `INTERNET` (**automatically granted at install time**)
  * Needed to communicate with the OTA server. Custota **does not and will never** communicate with any server outside of the configured OTA server. There are no ads, analytics, or any sort of tracking.
* `MANAGE_CARRIER_OEM_UNLOCK_STATE`, `MANAGE_USER_OEM_UNLOCK_STATE`, `READ_OEM_UNLOCK_STATE` (**automatically granted by system app permissions**)
  * Needed to show the bootloader unlock status.
* `POST_NOTIFICATIONS` (**must be granted by the user**)
  * Android requires a notification to be shown in order for the updater service to reliably run in the background.
* `REBOOT` (**automatically granted by system app permissions**)
  * Needed to reboot the device when the user explicitly presses the reboot button in Custota's notification after an update is installed.
* `RECEIVE_BOOT_COMPLETED` (**automatically granted at install time**)
  * Needed to schedule periodic update checks
* `WAKE_LOCK` (**automatically granted at install time**)
  * Needed to keep the CPU awake while an update is being installed.

## Advanced features

### Debug mode

Custota has hidden debug options that can be enabled or disabled by long pressing the version number.

### Logs

To access the Custota's logs, enable debug mode and press `Open log directory` to open the log directory in the system file manager (DocumentsUI). Or alternatively, browse to `/sdcard/Android/com.chiller3.custota/files` manually.

* `check.log`, `install.log`, and `revert.log`: Logs for the last check/install/revert operation.
* `crash.log`: Logs for the last crash.
* `/data/local/tmp/custota_selinux.log`: Logs for the SELinux changes made during boot.
  * This log cannot be saved to the normal log directory because it is written prior to the user unlocking the device for the first time after booting.

When reporting bugs, please include the log files as it is extremely helpful for identifying what might be going wrong. The logs should contain no sensitive information besides the OTA URLs.

(To monitor `update_engine`'s own logs, run `adb logcat '*:S' update_engine`.)

### Reinstallation

For testing, Custota can allow the current OS version (i.e. matching build fingerprint) to be reinstalled. To do so, enable debug mode and then enable the `Allow reinstall` toggle. Make sure to not enable `Automatically install updates` at the same time or else the current OS version will be reinstalled after every reboot because it's always seen as a valid update.

### Reverting an update

Normally, an update can be cancelled by presing the `Cancel` button in the notification while it is being downloaded or installed. However, if the opportunity to do so was missed and the update has already been installed, the update can be reverted by enabling debug mode and pressing the `Revert completed update` option. This stops the bootloader slot from being switched on reboot. Note that an update can only be reverted if the device hasn't been rebooted yet.

## How it works

The A/B update process in Android is handled by a builtin component called `update_engine`. The engine is used both for sideloading OTA updates when booted into recovery mode and for regular OTA updates while booted into Android. It is responsible for checking the signature of `payload.bin` inside the OTA zip against `/system/etc/security/otacerts.zip`, verifying existing partition checksums (for incremental updates), and then installing the payload. It also handles the download process when used in the streaming mode, which is always requested by Custota. Custota itself is responsible for the other parts, such as checking for updates, verifying compatibility, and preventing downgrades (which could cause the device to be unbootable due to Android Verified Boot's rollback index mechanism).

In order for Custota to talk to `update_engine` or even discover that the component exists, the SELinux policy must be modified to allow this access. The module ships with a [script](./app/module/post-fs-data.sh) that these modifications (non-persistently) on boot. This script is the only time root access is used.

There are two parts to the SELinux changes:

1. There's a [`custota_selinux` native executable](./app/src/main/cpp/custota_selinux) that performs all of the policy modifications. It takes the `untrusted_app` domain and makes a copy of it as `custota_app`. Then, it adds the relevant rules to allow only `custota_app` to access `update_engine`. The domain is copied from `untrusted_app` instead of the normal `priv_app` domain that is assigned to system apps because Custota does not require any of the additional privileges that would have been granted by `priv_app`.

2. An `seapp_contexts` rule is added to `/dev/selinux/apex_seapp_contexts`, which actually sets up the association between Custota (app package ID: `com.chiller3.custota`) and the new SELinux domain (`custota_app`).

These changes help limit Custota's privileges to exactly what is needed and avoids potentially increasing the attack surface via other apps.

### HTTPS

One caveat about `update_engine` is that it uses its own trust store for CA certificates at `/system/etc/security/cacerts_google`. To work around this, Custota's module will [override this directory](./app/module/customize.sh) to match the system and user 0 (primary user) trust store. It does so by copying all certificates from:

* `/apex/com.android.conscrypt/cacerts` (updatable system trust store on Android 14+)
* `/system/etc/security/cacerts` (system trust store on Android 13)
* `/data/misc/user/0/cacerts-added` (primary user trust store)

Then, any certificate with a matching name in `/data/misc/user/0/cacerts-removed` is removed, in case the user revoked its trust. These operations are done at module installation time. Custota needs to be reflashed for changes to CA certificates to take effect.

## Verifying digital signatures

Both the zip file and the APK contained within are digitally signed.

### Verifying zip file signature

First, save the public key to a file listing the keys to be trusted.

```bash
echo 'custota ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOe6/tBnO7xZhAWXRj3ApUYgn+XZ0wnQiXM8B7tPgv4' > custota_trusted_keys
```

Then, verify the signature of the zip file using the list of trusted keys.

```bash
ssh-keygen -Y verify -f custota_trusted_keys -I custota -n file -s Custota-<version>-release.zip.sig < Custota-<version>-release.zip
```

If the file is successfully verified, the output will be:

```
Good "file" signature for custota with ED25519 key SHA256:Ct0HoRyrFLrnF9W+A/BKEiJmwx7yWkgaW/JvghKrboA
```

### Verifying apk signature

First, extract the apk from the zip and then run:

```
apksigner verify --print-certs system/priv-app/com.chiller3.custota/app-release.apk
```

Then, check that the SHA-256 digest of the APK signing certificate is:

```
35749a70d9b855fe1a6262537db529fabc0ea24d1115ceb82835bf5a589578ae
```

## Building from source

Custota can be built like most other Android apps using Android Studio or the gradle command line.

To build the APK:

```bash
./gradlew assembleDebug
```

To build the Magisk/KernelSU module zip (which automatically runs the `assembleDebug` task if needed):

```bash
./gradlew zipDebug
```

The output file is written to `app/build/distributions/debug/`. The APK will be signed with the default autogenerated debug key.

To create a release build with a specific signing key, set up the following environment variables:

```bash
export RELEASE_KEYSTORE=/path/to/keystore.jks
export RELEASE_KEY_ALIAS=alias_name

read -r -s RELEASE_KEYSTORE_PASSPHRASE
read -r -s RELEASE_KEY_PASSPHRASE
export RELEASE_KEYSTORE_PASSPHRASE
export RELEASE_KEY_PASSPHRASE
```

and then build the release zip:

```bash
./gradlew zipRelease
```

## Contributing

Bug fix and translation pull requests are welcome and much appreciated!

If you are interested in implementing a new feature and would like to see it included in Custota, please open an issue to discuss it first. I intend for Custota to be as simple and low-maintenance as possible, so I am not too inclined to add new features, but I could be convinced otherwise.

## License

Custota is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
