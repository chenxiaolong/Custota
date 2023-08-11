<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0 @user] to link to pull requests. Then run:

        ./gradlew changelogUpdateLinks

    to update the actual links at the bottom of the file.
-->

### Version 2.0

* Add support for signed OTA metadata ([PR #2 @chenxiaolong])
    * **This is a breaking change.** A new `.csig` file needs to be generated for each OTA. See [the documentation](./README.md#ota-server) for instructions.

### Version 1.1

* Add section for bootloader unlock status ([PR #1 @chenxiaolong])

### Version 1.0

* Initial release

<!-- Do not manually edit the lines below. Use `./gradlew changelogUpdateLinks` to regenerate. -->
[PR #1 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/1
[PR #2 @chenxiaolong]: https://github.com/chenxiaolong/Custota/pull/2
