/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.annotation.SuppressLint
import android.content.Context
import android.net.Network
import android.os.Build
import android.os.IUpdateEngine
import android.os.IUpdateEngineCallback
import android.os.Parcelable
import android.os.PowerManager
import android.util.Log
import com.chiller3.custota.BuildConfig
import com.chiller3.custota.Preferences
import com.chiller3.custota.extension.toSingleLineString
import com.chiller3.custota.wrapper.ServiceManagerProxy
import kotlinx.parcelize.Parcelize
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.roundToInt

class UpdaterThread(
    private val context: Context,
    private val network: Network?,
    private val action: Action,
    private val listener: UpdaterThreadListener,
) : Thread() {
    private val updateEngine = IUpdateEngine.Stub.asInterface(
        ServiceManagerProxy.getServiceOrThrow("android.os.UpdateEngineService"))

    private val prefs = Preferences(context)

    private lateinit var logcatProcess: Process

    // If we crash and restart while paused, the user will need to pause and unpause to resume
    // because update_engine does not report the pause state.
    var isPaused: Boolean = false
        get() = synchronized(this) { field }
        set(value) {
            synchronized(this) {
                Log.d(TAG, "Updating pause state: $value")
                if (value) {
                    updateEngine.suspend()
                } else {
                    updateEngine.resume()
                }
                field = value
            }
        }

    private var engineIsBound = false
    private val engineStatusLock = ReentrantLock()
    private val engineStatusCondition = engineStatusLock.newCondition()
    private var engineStatus = -1
    private val engineErrorLock = ReentrantLock()
    private val engineErrorCondition = engineErrorLock.newCondition()
    private var engineError = -1

    private val engineCallback = object : IUpdateEngineCallback.Stub() {
        override fun onStatusUpdate(status: Int, percentage: Float) {
            val statusMsg = UpdateEngineStatus.toString(status)
            Log.d(TAG, "onStatusUpdate($statusMsg, ${percentage * 100}%)")

            engineStatusLock.withLock {
                engineStatus = status
                engineStatusCondition.signalAll()
            }

            val max = 100
            val current = (percentage * 100).roundToInt()

            when (status) {
                UpdateEngineStatus.DOWNLOADING -> ProgressType.UPDATE
                UpdateEngineStatus.VERIFYING -> ProgressType.VERIFY
                UpdateEngineStatus.FINALIZING -> ProgressType.FINALIZE
                else -> null
            }?.let {
                listener.onUpdateProgress(this@UpdaterThread, it, current, max)
            }
        }

        override fun onPayloadApplicationComplete(errorCode: Int) {
            val errorMsg = UpdateEngineError.toString(errorCode)
            Log.d(TAG, "onPayloadApplicationComplete($errorMsg)")

            engineErrorLock.withLock {
                engineError = errorCode
                engineErrorCondition.signalAll()
            }
        }
    }

    init {
        if (action != Action.REVERT && network == null) {
            throw IllegalStateException("Network is required for non-revert actions")
        }

        updateEngine.bind(engineCallback)
        engineIsBound = true
    }

    protected fun finalize() {
        // In case the thread is somehow not started
        unbind()
    }

    private fun unbind() {
        synchronized(this) {
            if (engineIsBound) {
                updateEngine.unbind(engineCallback)
                engineIsBound = false
            }
        }
    }

    private fun waitForStatus(block: (Int) -> Boolean): Int {
        engineStatusLock.withLock {
            while (!block(engineStatus)) {
                engineStatusCondition.await()
            }
            return engineStatus
        }
    }

    private fun waitForError(block: (Int) -> Boolean): Int {
        engineErrorLock.withLock {
            while (!block(engineError)) {
                engineErrorCondition.await()
            }
            return engineError
        }
    }

    fun cancel() {
        updateEngine.cancel()
    }

    private fun openUrl(url: URL, authorization: String?): HttpURLConnection {
        val c = network!!.openConnection(url) as HttpURLConnection
        c.connectTimeout = TIMEOUT_MS
        c.readTimeout = TIMEOUT_MS
        c.setRequestProperty("User-Agent", USER_AGENT)
        if (authorization != null) {
            c.setRequestProperty("Authorization", authorization)
        }
        return c
    }

    /** Download and parse update info JSON file. */
    private fun downloadUpdateInfo(url: URL): UpdateInfo {
        val data = openUrl(url, null).inputStream.bufferedReader().use {
            JSONObject(it.readText())
        }

        return UpdateInfo.fromJson(data)
    }

    /**
     * Download a chunk of the file at the given [offset] and [size]. The server must support byte
     * ranges. If the server returns too few or too many bytes, then the download will fail.
     *
     * @param output Not closed by this function
     */
    private fun downloadRangeToStream(
        url: URL,
        authorization: String?,
        offset: Long,
        size: Long,
        output: OutputStream,
    ) {
        val connection = openUrl(url, authorization)
        connection.setRequestProperty("Range", "bytes=$offset-${offset + size - 1}")
        connection.connect()

        if (connection.responseCode / 100 != 2) {
            throw IOException("Got ${connection.responseCode} (${connection.responseMessage}) for $url")
        }

        if (connection.getHeaderField("Accept-Ranges") != "bytes") {
            throw IOException("Server does not support byte ranges")
        }

        if (connection.contentLengthLong != size) {
            throw IOException("Expected $size bytes, but Content-Length is ${connection.contentLengthLong}")
        }

        connection.inputStream.use { input ->
            val buf = ByteArray(16384)
            var downloaded = 0L

            while (downloaded < size) {
                val toRead = java.lang.Long.min(buf.size.toLong(), size - downloaded).toInt()
                val n = input.read(buf, 0, toRead)
                if (n <= 0) {
                    break
                }

                output.write(buf, 0, n)
                downloaded += n.toLong()
            }

            if (downloaded != size) {
                throw IOException("Unexpected EOF after downloading $downloaded bytes (expected $size bytes)")
            } else if (input.read() != -1) {
                throw IOException("Server returned more data than expected (expected $size bytes)")
            }
        }
    }

    /**
     * Parse key/value pairs from properties-style files.
     *
     * The OTA property files format has equals-delimited key/value pairs, one on each line.
     * Extraneous newlines, comments, and duplicate keys are not allowed.
     */
    private fun parseKeyValuePairs(data: String): Map<String, String> {
        val result = hashMapOf<String, String>()

        for (line in data.lineSequence()) {
            if (line.isEmpty()) {
                continue
            }

            val pieces = line.split("=", limit = 2)
            if (pieces.size != 2) {
                throw IOException("Invalid property file line: $line")
            } else if (pieces[0] in result) {
                throw IOException("Duplicate property file key: ${pieces[0]}")
            }

            result[pieces[0]] = pieces[1]
        }

        return result
    }

    /** Parse property file entries from the relevant OTA metadata file value. */
    private fun parsePropertyFiles(value: String): List<PropertyFile> {
        val result = mutableListOf<PropertyFile>()

        for (segment in value.splitToSequence(',')) {
            // Trimmed because the last item will have padding
            val pieces = segment.trimEnd().split(':')
            if (pieces.size != 3) {
                throw IOException("Invalid property files segment: $segment")
            }

            val name = pieces[0]
            val offset = pieces[1].toLongOrNull()
                ?: throw IOException("Invalid property files entry offset: ${pieces[1]}")
            val size = pieces[2].toLongOrNull()
                ?: throw IOException("Invalid property files entry size: ${pieces[2]}")

            result.add(PropertyFile(name, offset, size))
        }

        return result
    }

    /** Download and parse key/value pairs file. */
    private fun downloadKeyValueFile(
        url: URL,
        authorization: String?,
        offset: Long,
        size: Long,
    ): Map<String, String> {
        val outputStream = ByteArrayOutputStream()
        downloadRangeToStream(url, authorization, offset, size, outputStream)

        return parseKeyValuePairs(outputStream.toString(Charsets.UTF_8))
    }

    /**
     * Download the OTA metadata and validate that the update is valid for the current system.
     *
     * Returns the metadata and the list of property file entries parsed from it.
     */
    private fun downloadAndCheckMetadata(
        url: URL,
        authorization: String?,
        offset: Long,
        size: Long,
    ): Pair<Map<String, String>, List<PropertyFile>> {
        val metadata = downloadKeyValueFile(url, authorization, offset, size)

        val get = { k: String ->
            metadata[k] ?: throw IOException("Missing key in OTA metadata: $k")
        }

        // Required
        val otaType = get("ota-type")
        val preDevice = get("pre-device")
        val postSecurityPatchLevel = get("post-security-patch-level")
        val postTimestamp = get("post-timestamp").toLong() * 1000

        if (otaType != "AB") {
            throw IllegalStateException("Not an A/B OTA package")
        } else if (preDevice != Build.DEVICE) {
            throw IllegalStateException("Mismatched device ID: " +
                    "current=${Build.DEVICE}, ota=$preDevice")
        } else if (postSecurityPatchLevel < Build.VERSION.SECURITY_PATCH) {
            throw IllegalStateException("Downgrading to older security patch is not allowed: " +
                    "current=${Build.VERSION.SECURITY_PATCH}, ota=$postSecurityPatchLevel")
        } else if (postTimestamp < Build.TIME) {
            throw IllegalStateException("Downgrading to older timestamp is not allowed: " +
                    "current=${Build.TIME}, ota=$postTimestamp")
        }

        // Optional
        val preBuildIncremental = metadata["pre-build-incremental"]
        val preBuild = metadata["pre-build"]
        val serialNo = metadata["serialno"]

        if (preBuildIncremental != null && preBuildIncremental != Build.VERSION.INCREMENTAL) {
            throw IllegalStateException("Mismatched incremental version: " +
                    "current=${Build.VERSION.INCREMENTAL}, ota=$preBuildIncremental")
        } else if (preBuild != null && preBuild != Build.FINGERPRINT) {
            throw IllegalStateException("Mismatched fingerprint: " +
                    "current=${Build.FINGERPRINT}, ota=$preBuild")
        } else if (serialNo != null) {
            throw IllegalStateException("OTAs for specific serial numbers are not supported")
        }

        // Property files
        val propertyFilesRaw = get("ota-property-files")
        val propertyFiles = parsePropertyFiles(propertyFilesRaw)

        // Sanity check to make sure the properties we just read are actually what will be used by
        // update_engine
        val metadataPropertyFile = propertyFiles.find { it.name == OtaPaths.METADATA_NAME }
            ?: throw IllegalStateException("Missing property file entry: ${OtaPaths.METADATA_NAME}")
        if (metadataPropertyFile.offset != offset) {
            throw IllegalStateException("Mismatched metadata offset: " +
                    "update_json=$offset, ota=${metadataPropertyFile.offset}")
        } else if (metadataPropertyFile.size != size) {
            throw IllegalStateException("Mismatched metadata size: " +
                    "update_json=$size, ota=${metadataPropertyFile.size}")
        }

        return Pair(metadata, propertyFiles)
    }

    /**
     * Download the payload metadata (protobuf in headers) and verify that the payload is valid for
     * this device.
     *
     * At a minimum, update_engine checks that the list of partitions in the OTA match the device.
     */
    @SuppressLint("SetWorldReadable")
    private fun downloadAndCheckPayloadMetadata(
        url: URL,
        authorization: String?,
        offset: Long,
        size: Long,
    ) {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.PAYLOAD_METADATA_NAME)

        try {
            file.outputStream().use {
                downloadRangeToStream(url, authorization, offset, size, it)
            }
            file.setReadable(true, false)

            updateEngine.verifyPayloadApplicable(file.absolutePath)
        } finally {
            file.delete()
        }
    }

    /**
     * Download the dm-verity care map to [OtaPaths.OTA_PACKAGE_DIR].
     *
     * Returns the path to the written file.
     */
    @SuppressLint("SetWorldReadable")
    private fun downloadCareMap(
        url: URL,
        authorization: String?,
        offset: Long,
        size: Long,
    ): File {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.CARE_MAP_NAME)

        try {
            file.outputStream().use {
                downloadRangeToStream(url, authorization, offset, size, it)
            }
            file.setReadable(true, false)
        } catch (e: Exception) {
            file.delete()
            throw e
        }

        return file
    }

    /** Synchronously check for updates. */
    private fun checkForUpdates(): CheckUpdateResult {
        val baseUrl = prefs.otaServerUrl ?: throw IllegalStateException("No URL configured")
        val updateInfoUrl = resolveUrl(baseUrl, "${Build.DEVICE}.json", true)
        Log.d(TAG, "Update info URL: $updateInfoUrl")

        val updateInfo = try {
            downloadUpdateInfo(updateInfoUrl)
        } catch (e: Exception) {
            throw IOException("Failed to download update info", e)
        }

        val otaPackageUrl = resolveUrl(updateInfoUrl, updateInfo.location, false)
        Log.d(TAG, "OTA package URL: $otaPackageUrl")

        val (metadata, propertyFiles) = downloadAndCheckMetadata(
            otaPackageUrl,
            updateInfo.authorization,
            updateInfo.metadataOffset,
            updateInfo.metadataSize,
        )

        Log.d(TAG, "OTA metadata: $metadata")
        Log.d(TAG, "Property files: $propertyFiles")

        val fingerprint = metadata["post-build"]
        var updateAvailable = fingerprint != Build.FINGERPRINT

        if (!updateAvailable) {
            Log.w(TAG, "Already up to date")

            if (prefs.allowReinstall) {
                Log.w(TAG, "Reinstalling at user's request")
                updateAvailable = true
            }
        }

        return CheckUpdateResult(
            updateAvailable,
            fingerprint,
            otaPackageUrl,
            updateInfo,
            propertyFiles,
        )
    }

    /** Asynchronously trigger the update_engine payload application. */
    private fun startInstallation(
        otaPackageUrl: URL,
        updateInfo: UpdateInfo,
        propertyFiles: List<PropertyFile>,
    ) {
        val getPf = { name: String ->
            propertyFiles.find { it.name == name }
                ?: throw IllegalStateException("Missing property files entry: $name")
        }

        val pfPayload = getPf(OtaPaths.PAYLOAD_NAME)
        val pfPayloadMetadata = getPf(OtaPaths.PAYLOAD_METADATA_NAME)
        val pfPayloadProperties = getPf(OtaPaths.PAYLOAD_PROPERTIES_NAME)
        val pfCareMap = propertyFiles.find { it.name == OtaPaths.CARE_MAP_NAME }

        Log.i(TAG, "Downloading payload metadata and checking compatibility")

        downloadAndCheckPayloadMetadata(
            otaPackageUrl,
            updateInfo.authorization,
            pfPayloadMetadata.offset,
            pfPayloadMetadata.size,
        )

        Log.i(TAG, "Downloading payload properties file")

        val payloadProperties = downloadKeyValueFile(
            otaPackageUrl,
            updateInfo.authorization,
            pfPayloadProperties.offset,
            pfPayloadProperties.size,
        )

        Log.i(TAG, "Downloading dm-verity care map file")

        if (pfCareMap != null) {
            downloadCareMap(
                otaPackageUrl,
                updateInfo.authorization,
                pfCareMap.offset,
                pfCareMap.size,
            )
        } else {
            Log.w(TAG, "OTA package does not have a dm-verity care map")
        }

        Log.i(TAG, "Passing payload information to update_engine")

        val engineProperties = HashMap(payloadProperties).apply {
            put("NETWORK_ID", network!!.networkHandle.toString())
            put("USER_AGENT", USER_AGENT_UPDATE_ENGINE)

            if (updateInfo.authorization != null) {
                Log.i(TAG, "Passing authorization header to update_engine")
                put("AUTHORIZATION", updateInfo.authorization)
            }

            if (prefs.skipPostInstall) {
                put("RUN_POST_INSTALL", "0")
            }
        }

        updateEngine.applyPayload(
            otaPackageUrl.toString(),
            pfPayload.offset,
            pfPayload.size,
            engineProperties.map { "${it.key}=${it.value}" }.toTypedArray(),
        )
    }

    private fun startLogcat() {
        assert(!this::logcatProcess.isInitialized) { "logcat already started" }

        Log.d(TAG, "Starting log file (${BuildConfig.VERSION_NAME})")

        val logcatFile = File(context.getExternalFilesDir(null),
            "${action.name.lowercase()}.log")
        logcatProcess = ProcessBuilder("logcat", "*:V")
            // This is better than -f because the logcat implementation calls fflush() when the
            // output stream is stdout.
            .redirectOutput(logcatFile)
            .redirectErrorStream(true)
            .start()
    }

    private fun stopLogcat() {
        assert(this::logcatProcess.isInitialized) { "logcat not started" }

        try {
            Log.d(TAG, "Stopping log file")

            // Give logcat a bit of time to flush the output. It does not have any special
            // handling to flush buffers when interrupted.
            sleep(1000)

            logcatProcess.destroy()
        } finally {
            logcatProcess.waitFor()
        }
    }

    @SuppressLint("WakelockTimeout")
    override fun run() {
        startLogcat()

        val pm = context.getSystemService(PowerManager::class.java)
        val wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG)

        try {
            wakeLock.acquire()

            listener.onUpdateProgress(this, ProgressType.INIT, 0, 0)

            Log.d(TAG, "Waiting for initial engine status")
            val status = waitForStatus { it != -1 }
            val statusStr = UpdateEngineStatus.toString(status)
            Log.d(TAG, "Initial status: $statusStr")

            if (action == Action.REVERT) {
                if (status == UpdateEngineStatus.UPDATED_NEED_REBOOT) {
                    Log.d(TAG, "Reverting new update because engine is pending reboot")
                    updateEngine.resetStatus()
                } else {
                    throw IllegalStateException("Cannot revert while in state: $statusStr")
                }

                val newStatus = waitForStatus { it != UpdateEngineStatus.UPDATED_NEED_REBOOT }
                val newStatusStr = UpdateEngineStatus.toString(newStatus)
                Log.d(TAG, "New status after revert: $newStatusStr")

                if (newStatus == UpdateEngineStatus.IDLE) {
                    listener.onUpdateResult(this, UpdateReverted)
                } else {
                    listener.onUpdateResult(this, UpdateFailed(newStatusStr))
                }
            } else if (status == UpdateEngineStatus.UPDATED_NEED_REBOOT) {
                // Resend success notification to remind the user to reboot. We can't perform any
                // further operations besides reverting.
                listener.onUpdateResult(this, UpdateNeedReboot)
            } else {
                if (status == UpdateEngineStatus.IDLE) {
                    Log.d(TAG, "Starting new update because engine is idle")

                    listener.onUpdateProgress(this, ProgressType.CHECK, 0, 0)

                    val checkUpdateResult = checkForUpdates()

                    if (!checkUpdateResult.updateAvailable) {
                        // Update not needed
                        listener.onUpdateResult(this, UpdateUnnecessary)
                        return
                    } else if (action == Action.CHECK) {
                        // Just alert that an update is available
                        listener.onUpdateResult(this,
                            UpdateAvailable(checkUpdateResult.fingerprint))
                        return
                    }

                    startInstallation(
                        checkUpdateResult.otaPackageUrl,
                        checkUpdateResult.updateInfo,
                        checkUpdateResult.propertyFiles,
                    )
                } else {
                    Log.w(TAG, "Monitoring existing update because engine is not idle")
                }

                val error = waitForError { it != -1 }
                val errorStr = UpdateEngineError.toString(error)
                Log.d(TAG, "Update engine result: $errorStr")

                if (UpdateEngineError.isUpdateSucceeded(error)) {
                    Log.d(TAG, "Successfully completed upgrade")
                    listener.onUpdateResult(this, UpdateSucceeded)
                } else if (error == UpdateEngineError.USER_CANCELED) {
                    Log.w(TAG, "User cancelled upgrade")
                    listener.onUpdateResult(this, UpdateCancelled)
                } else {
                    throw Exception(errorStr)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to install update", e)
            listener.onUpdateResult(this, UpdateFailed(e.toSingleLineString()))
        } finally {
            wakeLock.release()
            unbind()

            try {
                stopLogcat()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to dump logcat", e)
            }
        }
    }

    private data class CheckUpdateResult(
        val updateAvailable: Boolean,
        val fingerprint: String?,
        val otaPackageUrl: URL,
        val updateInfo: UpdateInfo,
        val propertyFiles: List<PropertyFile>,
    )

    private data class PropertyFile(
        val name: String,
        val offset: Long,
        val size: Long,
    )

    private data class UpdateInfo(
        val location: String,
        val authorization: String?,
        val metadataOffset: Long,
        val metadataSize: Long,
    ) {
        companion object {
            fun fromJson(json: JSONObject): UpdateInfo {
                // We only support full OTAs right now
                val full = json.getJSONObject("full")

                val location = full.getString("location")
                val authorization = if (full.isNull("authorization")) {
                    null
                } else {
                    full.getString("authorization")
                }
                val metadataOffset = full.getLong("metadata_offset")
                val metadataSize = full.getLong("metadata_size")

                return UpdateInfo(location, authorization, metadataOffset, metadataSize)
            }
        }
    }

    @Parcelize
    enum class Action : Parcelable {
        CHECK,
        INSTALL,
        REVERT,
    }

    sealed interface Result {
        val isError : Boolean
    }

    data class UpdateAvailable(val fingerprint: String?) : Result {
        override val isError = false
    }

    data object UpdateUnnecessary : Result {
        override val isError = false
    }

    data object UpdateSucceeded : Result {
        override val isError = false
    }

    /** Update succeeded in a previous updater run. */
    data object UpdateNeedReboot : Result {
        override val isError = false
    }

    data object UpdateReverted : Result {
        override val isError = false
    }

    data object UpdateCancelled : Result {
        override val isError = true
    }

    data class UpdateFailed(val errorMsg: String) : Result {
        override val isError = true
    }

    enum class ProgressType {
        INIT,
        CHECK,
        UPDATE,
        VERIFY,
        FINALIZE,
    }

    interface UpdaterThreadListener {
        fun onUpdateResult(thread: UpdaterThread, result: Result)

        fun onUpdateProgress(thread: UpdaterThread, type: ProgressType, current: Int, max: Int)
    }

    companion object {
        private val TAG = UpdaterThread::class.java.simpleName

        private const val USER_AGENT = "${BuildConfig.APPLICATION_ID}/${BuildConfig.VERSION_NAME}"
        private val USER_AGENT_UPDATE_ENGINE = "$USER_AGENT update_engine/${Build.VERSION.SDK_INT}"

        private const val TIMEOUT_MS = 30_000

        private fun resolveUrl(base: URL, str: String, forceBaseAsDir: Boolean): URL {
            var raw = base.toString()
            if (forceBaseAsDir && !raw.endsWith('/')) {
                raw += '/'
            }

            return URI(raw).resolve(str).toURL()
        }
    }
}