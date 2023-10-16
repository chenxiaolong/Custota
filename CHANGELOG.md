<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        ./gradlew changelogUpdateLinks

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Work around GrapheneOS 14 that causes Custota to crash ([Issue #22], [PR #23])

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
