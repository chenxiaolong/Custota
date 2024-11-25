<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        ./gradlew changelogUpdateLinks

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Rebase icon off latest material system update icon ([PR #102])
* Update all dependencies ([PR #105])
* Only apply the unmetered network and battery level restrictions to the actual OTA installation, not the update check ([Issue #104], [PR #106])
  * This also fixes the post-reboot OTA cleanup monitoring job and the revert update job so that they don't wait for a network connection or sufficient battery before running

### Version 5.2

* Enable predictive back gestures ([PR #98])
* Let Magisk/KernelSU handle mounting `/system/etc/selinux/plat_seapp_contexts` ([PR #99], [PR #101])
* Update all dependencies ([PR #100])

### Version 5.1

* Add new `--csig-version` option to custota-tool to allow generating version 1 csig files ([Issue #94], [PR #95])
* Ignore unknown fields in csig files and update JSON files to allow better backwards compatibility in the future ([Issue #94], [PR #96])

### Version 5.0

* Use the vbmeta digest in addition to the fingerprint to determine if the OS is update to date ([Issue #38], [PR #92])
  * This means Custota will now report that an update is available if the OTA's contents changed, even if the OS version remains the same. OTAs where only Magisk/KernelSU/etc. is updated will now be properly detected as updates.
  * This feature bumps the `.csig` file format version from 1 to 2. Older versions of Custota **cannot** read new version 2 files, but newer versions of Custota **can** read old version 1 files.
* Fix Cursor resource leak ([PR #90])
* Minor notification code cleanup ([PR #91])
* Update all dependencies ([PR #93])

### Version 4.13

* Fix compatibility when installed alongside other modules that modify `plat_seapp_contexts` with upcoming versions of Magisk ([PR #89])

### Version 4.12

* Fix custom CA certificates being mounted incorrectly ([Issue #87], [PR #88])
  * If you use custom CA certificates, you will need to regenerate and flash the `system-ca-certs` module

### Version 4.11

* Target API 35 ([PR #82])
* Add support for local directory installation on older devices that use sdcardfs, like the Pixel 4a ([Issue #83], [PR #84])

### Version 4.10

* Fix "OS is already up to date" notification showing after a reboot ([PR #81])

### Version 4.9

* Show notification for OTA cleanup phase following the reboot after an OTA is installed ([PR #78])
* Fix the initializing OTA updater notification message being shown longer than expected ([PR #78])
* Fix the pause, resume, and cancel buttons being shown during phases where they cannot work ([PR #78])
* Show an indeterminate progress bar until the progress reaches 1% because the finalization and cleanup phases don't report any progress ([PR #80])

### Version 4.8

* Fix incorrect gradle inputs causing Rust source code to not be rebuilt ([PR #70])
* Use Material 3 switches for switch preferences ([PR #71])
* Update dependencies ([PR #73])
* custota-selinux: Prevent updating the modification timestamp of `/sys/fs/selinux/load` ([Issue #72], [PR #74])
  * Please note there are no plans to implement further ways of evading detection by apps. This workaround just happened to be easy enough to implement.

### Version 4.7

* Work around Android builds where the job scheduler implementation implementation is broken and returns a null `Network` instance ([Issue #68], [PR #69])
  * This appears to happen to some folks on the Android 15 beta. If this Android bug occurs, Custota will show a notification saying the `Require Unmetered Network` option must be disabled. This is required to work around the bug.

### Version 4.6

* custota-selinux: Move workaround for broken linking on x86_64 from sepatch to cargo-android ([PR #65])
* post-fs-data: Mount `plat_seapp_contexts` directly for better compatibility with other modules also need to modify the file ([PR #66])
* Update checksum for `tensorflow-lite-metadata-0.1.0-rc2.pom` dependency ([PR #67])

### Version 4.5

* Log boot script output to logcat ([PR #62])
* Replace custota-selinux with a new implementation based on the sepatch library ([PR #63])
* Update all dependencies ([PR #64])

### Version 4.4

* Update all dependencies ([PR #59])
* Add prebuilt custota-tool binary for Android (aarch64) ([Issue #60], [PR #61])

### Version 4.3

* Build universal binary for macOS ([PR #57])

### Version 4.2

* Fix `update_engine` failing with `9/DOWNLOAD_TRANSFER_ERROR` on newer Android versions ([PR #56])

### Version 4.1

* Add debug option for installing custom csig validation certs ([Issue #47], [PR #48])
* Update Kotlin and Rust dependencies ([PR #49])
* Work around Android builds that lie about the security patch release in `Build.VERSION.SECURITY_PATCH` ([Issue #51], [PR #52])
* Show a notification instead of hard crashing when Custota's `/system/etc/sysconfig/` is being ignored by Android ([Issue #51], [PR #53])
* Work around crashes due to Android not invalidating the package manager cache when a device has the wrong system time during boot ([Issue #51], [PR #54])

### Version 4.0

This release has no changes for most folks, but does have a breaking change for those using custom CA certificates:

* Custota used to automatically copy all user CA certificates from Android's settings into `update_engine`'s trust store. However, as of Android 14 QPR2, `update_engine` has been changed to use the regular system trust store. Instead of adapting the feature to copy user CA certificates into the system trust store, the feature has been removed because it would impact the entire system instead of just `update_engine`.
* The custom CA certificate use case is still fully supported. The certificate just needs to be explicitly installed now. Please see [this section of the documentation](./README.md#https) for details on how to do so.

Changes:

* Replace automatic installation of user CA certificates with a certificate module zip generator ([Issue #42], [PR #43])

### Version 3.1

* Switch to modifying `/system/etc/selinux/plat_seapp_contexts` ([Issue #40], [PR #41])
  * Fixes `ServiceNotFoundException` when connecting to `update_engine` on Android 14 QPR2 (2024 March security update)

### Version 3.0

Happy New Year! avbroot 3.0.0 was also released today, which added support for patching the system partition's `otacerts.zip`. With that change, Custota's `customotacerts` module is no longer needed.

After updating to an OTA that was patched by avbroot 3.0.0 or newer, the `customotacerts` module can be safely uninstalled.

Changes:

* Update all dependencies ([PR #31])
* Build precompiled `custota-tool` executables as statically linked executables ([PR #32], [PR #35])
* Fix minor clippy warning ([PR #33])
* Remove `customotacerts` module ([PR #34])

### Version 2.5

* Update all dependencies ([PR #26])
* Add support for installing from a local directory ([Issue #25], [PR #27])
* Check for Content-Range in HTTP responses instead of Accept-Ranges ([Issue #29], [PR #30])
  * Fixes compatibility with nginx

### Version 2.4

* Work around GrapheneOS 14 change that causes Custota to crash ([Issue #22], [PR #23])

### Version 2.3

It's Android 14 release day! Any version of Custota can be used to initially upgrade to Android 14, but Custota 2.2 or newer is needed for future OTAs to be installed.

Changes:

* Update dependencies ([PR #17], [PR #20], [PR #21])
* Fix non-UTF-8 paths not being accepted by custota-tool's `--cert` option on Linux ([PR #18])

### Version 2.2

* Fix crash when showing error notification if the app cannot connect to `update_engine` ([Issue #11], [PR #12])
* Explicitly create `/dev/selinux` during boot to fix SELinux patches on Android 14 ([Issue #11], [PR #14])
* Refactor custota-tool to use code from avbroot ([PR #13])

### Version 2.1

* Add Vietnamese translations ([PR #6])
* Fix crash on initial app launch after installation ([Issue #7], [PR #8])
* Add hint text for OTA server URL text box ([Issue #5], [PR #9])
* Document how periodic update checks work ([Issue #5], [PR #10])

### Version 2.0

* Add support for signed OTA metadata ([PR #2])
    * **This is a breaking change.** A new `.csig` file needs to be generated for each OTA. See [the documentation](./README.md#ota-server) for instructions.

### Version 1.1

* Add section for bootloader unlock status ([PR #1])

### Version 1.0

* Initial release

<!-- Do not manually edit the lines below. Use `./gradlew changelogUpdateLinks` to regenerate. -->
[Issue #5]: https://github.com/chenxiaolong/Custota/issues/5
[Issue #7]: https://github.com/chenxiaolong/Custota/issues/7
[Issue #11]: https://github.com/chenxiaolong/Custota/issues/11
[Issue #22]: https://github.com/chenxiaolong/Custota/issues/22
[Issue #25]: https://github.com/chenxiaolong/Custota/issues/25
[Issue #29]: https://github.com/chenxiaolong/Custota/issues/29
[Issue #38]: https://github.com/chenxiaolong/Custota/issues/38
[Issue #40]: https://github.com/chenxiaolong/Custota/issues/40
[Issue #42]: https://github.com/chenxiaolong/Custota/issues/42
[Issue #47]: https://github.com/chenxiaolong/Custota/issues/47
[Issue #51]: https://github.com/chenxiaolong/Custota/issues/51
[Issue #60]: https://github.com/chenxiaolong/Custota/issues/60
[Issue #68]: https://github.com/chenxiaolong/Custota/issues/68
[Issue #72]: https://github.com/chenxiaolong/Custota/issues/72
[Issue #83]: https://github.com/chenxiaolong/Custota/issues/83
[Issue #87]: https://github.com/chenxiaolong/Custota/issues/87
[Issue #94]: https://github.com/chenxiaolong/Custota/issues/94
[Issue #104]: https://github.com/chenxiaolong/Custota/issues/104
[PR #1]: https://github.com/chenxiaolong/Custota/pull/1
[PR #2]: https://github.com/chenxiaolong/Custota/pull/2
[PR #6]: https://github.com/chenxiaolong/Custota/pull/6
[PR #8]: https://github.com/chenxiaolong/Custota/pull/8
[PR #9]: https://github.com/chenxiaolong/Custota/pull/9
[PR #10]: https://github.com/chenxiaolong/Custota/pull/10
[PR #12]: https://github.com/chenxiaolong/Custota/pull/12
[PR #13]: https://github.com/chenxiaolong/Custota/pull/13
[PR #14]: https://github.com/chenxiaolong/Custota/pull/14
[PR #17]: https://github.com/chenxiaolong/Custota/pull/17
[PR #18]: https://github.com/chenxiaolong/Custota/pull/18
[PR #20]: https://github.com/chenxiaolong/Custota/pull/20
[PR #21]: https://github.com/chenxiaolong/Custota/pull/21
[PR #23]: https://github.com/chenxiaolong/Custota/pull/23
[PR #26]: https://github.com/chenxiaolong/Custota/pull/26
[PR #27]: https://github.com/chenxiaolong/Custota/pull/27
[PR #30]: https://github.com/chenxiaolong/Custota/pull/30
[PR #31]: https://github.com/chenxiaolong/Custota/pull/31
[PR #32]: https://github.com/chenxiaolong/Custota/pull/32
[PR #33]: https://github.com/chenxiaolong/Custota/pull/33
[PR #34]: https://github.com/chenxiaolong/Custota/pull/34
[PR #35]: https://github.com/chenxiaolong/Custota/pull/35
[PR #41]: https://github.com/chenxiaolong/Custota/pull/41
[PR #43]: https://github.com/chenxiaolong/Custota/pull/43
[PR #48]: https://github.com/chenxiaolong/Custota/pull/48
[PR #49]: https://github.com/chenxiaolong/Custota/pull/49
[PR #52]: https://github.com/chenxiaolong/Custota/pull/52
[PR #53]: https://github.com/chenxiaolong/Custota/pull/53
[PR #54]: https://github.com/chenxiaolong/Custota/pull/54
[PR #56]: https://github.com/chenxiaolong/Custota/pull/56
[PR #57]: https://github.com/chenxiaolong/Custota/pull/57
[PR #59]: https://github.com/chenxiaolong/Custota/pull/59
[PR #61]: https://github.com/chenxiaolong/Custota/pull/61
[PR #62]: https://github.com/chenxiaolong/Custota/pull/62
[PR #63]: https://github.com/chenxiaolong/Custota/pull/63
[PR #64]: https://github.com/chenxiaolong/Custota/pull/64
[PR #65]: https://github.com/chenxiaolong/Custota/pull/65
[PR #66]: https://github.com/chenxiaolong/Custota/pull/66
[PR #67]: https://github.com/chenxiaolong/Custota/pull/67
[PR #69]: https://github.com/chenxiaolong/Custota/pull/69
[PR #70]: https://github.com/chenxiaolong/Custota/pull/70
[PR #71]: https://github.com/chenxiaolong/Custota/pull/71
[PR #73]: https://github.com/chenxiaolong/Custota/pull/73
[PR #74]: https://github.com/chenxiaolong/Custota/pull/74
[PR #78]: https://github.com/chenxiaolong/Custota/pull/78
[PR #80]: https://github.com/chenxiaolong/Custota/pull/80
[PR #81]: https://github.com/chenxiaolong/Custota/pull/81
[PR #82]: https://github.com/chenxiaolong/Custota/pull/82
[PR #84]: https://github.com/chenxiaolong/Custota/pull/84
[PR #88]: https://github.com/chenxiaolong/Custota/pull/88
[PR #89]: https://github.com/chenxiaolong/Custota/pull/89
[PR #90]: https://github.com/chenxiaolong/Custota/pull/90
[PR #91]: https://github.com/chenxiaolong/Custota/pull/91
[PR #92]: https://github.com/chenxiaolong/Custota/pull/92
[PR #93]: https://github.com/chenxiaolong/Custota/pull/93
[PR #95]: https://github.com/chenxiaolong/Custota/pull/95
[PR #96]: https://github.com/chenxiaolong/Custota/pull/96
[PR #98]: https://github.com/chenxiaolong/Custota/pull/98
[PR #99]: https://github.com/chenxiaolong/Custota/pull/99
[PR #100]: https://github.com/chenxiaolong/Custota/pull/100
[PR #101]: https://github.com/chenxiaolong/Custota/pull/101
[PR #102]: https://github.com/chenxiaolong/Custota/pull/102
[PR #105]: https://github.com/chenxiaolong/Custota/pull/105
[PR #106]: https://github.com/chenxiaolong/Custota/pull/106
