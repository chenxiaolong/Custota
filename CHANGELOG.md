<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0 @user] to link to pull requests. Then run:

        ./gradlew changelogUpdateLinks

    to update the actual links at the bottom of the file.
-->

### Version 2.1

* Add Vietnamese translations ([PR #6 @archandanime])
* Fix crash on initial app launch after installation ([Issue #7], [PR #8 @chenxiaolong])
* Add hint text for OTA server URL text box ([Issue #5], [PR #9 @chenxiaolong])
* Document how periodic update checks work ([Issue #5], [PR #10 @chenxiaolong])

### Version 2.0

* Add support for signed OTA metadata ([PR #2 @chenxiaolong])
    * **This is a breaking change.** A new `.csig` file needs to be generated for each OTA. See [the documentation](./README.md#ota-server) for instructions.

### Version 1.1

* Add section for bootloader unlock status ([PR #1 @chenxiaolong])

### Version 1.0

* Initial release

<!-- Do not manually edit the lines below. Use `./gradlew changelogUpdateLinks` to regenerate. -->
[Issue #5]: https://github.com/chenxiaolong/Custota/issues/5
[Issue #7]: https://github.com/chenxiaolong/Custota/issues/7
[PR #1 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/1
[PR #2 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/2
[PR #6 @archandanime]: https://github.com/chenxiaolong/Custota/pull/6
[PR #8 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/8
[PR #9 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/9
[PR #10 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/10
