<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        ./gradlew changelogUpdateLinks

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Add debug option for installing custom csig validation certs ([Issue #47], [PR #48])
* Update Kotlin and Rust dependencies ([PR #49])
* Work around Android builds that lie about the security patch release in `Build.VERSION.SECURITY_PATCH` ([Issue #51], [PR #52])

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
[Issue #40]: https://github.com/chenxiaolong/Custota/issues/40
[Issue #42]: https://github.com/chenxiaolong/Custota/issues/42
[Issue #47]: https://github.com/chenxiaolong/Custota/issues/47
[Issue #51]: https://github.com/chenxiaolong/Custota/issues/51
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
