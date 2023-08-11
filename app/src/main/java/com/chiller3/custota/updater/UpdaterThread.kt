/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(ExperimentalStdlibApi::class, ExperimentalSerializationApi::class)

package com.chiller3.custota.updater

import android.annotation.SuppressLint
import android.content.Context
import android.net.Network
import android.os.Build
import android.os.IUpdateEngine
import android.os.IUpdateEngineCallback
import android.os.Parcelable
import android.os.PowerManager
import android.ota.OtaPackageMetadata.OtaMetadata
import android.util.Log
import com.chiller3.custota.BuildConfig
import com.chiller3.custota.Preferences
import com.chiller3.custota.extension.toSingleLineString
import com.chiller3.custota.wrapper.ServiceManagerProxy
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
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
    // NOTE: This is not implemented.
    private val authorization: String? = null

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

    private fun openUrl(url: URL): HttpURLConnection {
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
        val updateInfo: UpdateInfo = openUrl(url).inputStream.use {
            Json.decodeFromStream(it)
        }
        Log.d(TAG, "Update info: $updateInfo")

        if (updateInfo.version != 2) {
            throw BadFormatException("Only UpdateInfo version 2 is supported")
        }

        return updateInfo
    }

    /**
     * Download a property file entry from the OTA zip. The server must support byte ranges. If the
     * server returns too few or too many bytes, then the download will fail.
     *
     * @param output Not closed by this function
     */
    private fun downloadPropertyFile(url: URL, pf: PropertyFile, output: OutputStream) {
        val connection = openUrl(url)
        connection.setRequestProperty("Range", "bytes=${pf.offset}-${pf.offset + pf.size - 1}")
        connection.connect()

        if (connection.responseCode / 100 != 2) {
            throw IOException("Got ${connection.responseCode} (${connection.responseMessage}) for $url")
        }

        if (connection.getHeaderField("Accept-Ranges") != "bytes") {
            throw IOException("Server does not support byte ranges")
        }

        if (connection.contentLengthLong != pf.size) {
            throw IOException("Expected ${pf.size} bytes, but Content-Length is ${connection.contentLengthLong}")
        }

        val md = MessageDigest.getInstance("SHA-256")

        connection.inputStream.use { input ->
            val buf = ByteArray(16384)
            var downloaded = 0L

            while (downloaded < pf.size) {
                val toRead = java.lang.Long.min(buf.size.toLong(), pf.size - downloaded).toInt()
                val n = input.read(buf, 0, toRead)
                if (n <= 0) {
                    break
                }

                md.update(buf, 0, n)
                output.write(buf, 0, n)
                downloaded += n.toLong()
            }

            if (downloaded != pf.size) {
                throw IOException("Unexpected EOF after downloading $downloaded bytes (expected ${pf.size} bytes)")
            } else if (input.read() != -1) {
                throw IOException("Server returned more data than expected (expected ${pf.size} bytes)")
            }
        }

        val sha256 = md.digest().toHexString()

        if (!pf.digest.equals(sha256, true)) {
            throw IOException("Expected sha256 ${pf.digest}, but have $sha256")
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
                throw BadFormatException("Invalid property file line: $line")
            } else if (pieces[0] in result) {
                throw BadFormatException("Duplicate property file key: ${pieces[0]}")
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
                throw BadFormatException("Invalid property files segment: $segment")
            }

            val name = pieces[0]
            val offset = pieces[1].toLongOrNull()
                ?: throw BadFormatException("Invalid property files entry offset: ${pieces[1]}")
            val size = pieces[2].toLongOrNull()
                ?: throw BadFormatException("Invalid property files entry size: ${pieces[2]}")

            result.add(PropertyFile(name, offset, size, null))
        }

        return result
    }

    /** Download and parse key/value pairs file. */
    private fun downloadKeyValueFile(url: URL, pf: PropertyFile): Map<String, String> {
        val outputStream = ByteArrayOutputStream()
        downloadPropertyFile(url, pf, outputStream)

        return parseKeyValuePairs(outputStream.toString(Charsets.UTF_8))
    }

    /** Download and verify signature of the csig file. */
    private fun downloadAndCheckCsig(csigUrl: URL): CsigInfo {
        val csigRaw = openUrl(csigUrl).inputStream.use { it.readBytes() }
        val csigCms = CMSSignedData(csigRaw)

        // Verify the signature against the same OTA certs as what's used for the payload.
        val csigValid = OtaPaths.otaCerts.any { cert ->
            csigCms.signerInfos.any { signerInfo ->
                signerInfo.verify(JcaSimpleSignerInfoVerifierBuilder().build(cert))
            }
        }
        if (!csigValid) {
            throw ValidationException("csig is not signed by a trusted key")
        }
        Log.d(TAG, "csig signature is valid")

        val csigInfoRaw = String(csigCms.signedContent.content as ByteArray)
        val csigInfo: CsigInfo = Json.decodeFromString(csigInfoRaw)
        Log.d(TAG, "csig info: $csigInfo")

        if (csigInfo.version != 1) {
            throw BadFormatException("Only CsigInfo version 1 is supported")
        }

        return csigInfo
    }

    /** Download the OTA metadata and validate that the update is valid for the current system. */
    private fun downloadAndCheckMetadata(
        url: URL,
        pf: PropertyFile,
        csigInfo: CsigInfo,
    ): OtaMetadata {
        val outputStream = ByteArrayOutputStream()
        downloadPropertyFile(url, pf, outputStream)

        val metadata = OtaMetadata.newBuilder().mergeFrom(outputStream.toByteArray()).build()
        Log.d(TAG, "OTA metadata: $metadata")

        // Required
        val preDevices = metadata.precondition.deviceList
        val postSecurityPatchLevel = metadata.postcondition.securityPatchLevel
        val postTimestamp = metadata.postcondition.timestamp * 1000

        if (metadata.type != OtaMetadata.OtaType.AB) {
            throw ValidationException("Not an A/B OTA package")
        } else if (!preDevices.contains(Build.DEVICE)) {
            throw ValidationException("Mismatched device ID: " +
                    "current=${Build.DEVICE}, ota=$preDevices")
        } else if (postSecurityPatchLevel < Build.VERSION.SECURITY_PATCH) {
            throw ValidationException("Downgrading to older security patch is not allowed: " +
                    "current=${Build.VERSION.SECURITY_PATCH}, ota=$postSecurityPatchLevel")
        } else if (postTimestamp < Build.TIME) {
            throw ValidationException("Downgrading to older timestamp is not allowed: " +
                    "current=${Build.TIME}, ota=$postTimestamp")
        }

        // Optional
        val preBuildIncremental = metadata.precondition.buildIncremental
        val preBuilds = metadata.precondition.buildList

        if (preBuildIncremental.isNotEmpty() && preBuildIncremental != Build.VERSION.INCREMENTAL) {
            throw ValidationException("Mismatched incremental version: " +
                    "current=${Build.VERSION.INCREMENTAL}, ota=$preBuildIncremental")
        } else if (preBuilds.isNotEmpty() && !preBuilds.contains(Build.FINGERPRINT)) {
            throw ValidationException("Mismatched fingerprint: " +
                    "current=${Build.FINGERPRINT}, ota=$preBuilds")
        }

        // Property files
        val propertyFilesRaw = metadata.getPropertyFilesOrThrow("ota-property-files")
        val propertyFiles = parsePropertyFiles(propertyFilesRaw)

        val invalidPropertyFiles = csigInfo.files.zip(propertyFiles)
            .filter { !it.first.equalsWithoutDigest(it.second) }

        if (invalidPropertyFiles.isNotEmpty()) {
            throw ValidationException(
                "csig files do not match metadata property files: $invalidPropertyFiles")
        }

        return metadata
    }

    /**
     * Download the payload metadata (protobuf in headers) and verify that the payload is valid for
     * this device.
     *
     * At a minimum, update_engine checks that the list of partitions in the OTA match the device.
     */
    @SuppressLint("SetWorldReadable")
    private fun downloadAndCheckPayloadMetadata(url: URL, pf: PropertyFile) {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.PAYLOAD_METADATA_NAME)

        try {
            file.outputStream().use { out ->
                downloadPropertyFile(url, pf, out)
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
    private fun downloadCareMap(url: URL, pf: PropertyFile): File {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.CARE_MAP_NAME)

        try {
            file.outputStream().use { out ->
                downloadPropertyFile(url, pf, out)
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

        val otaUrl = resolveUrl(updateInfoUrl, updateInfo.full.locationOta, false)
        Log.d(TAG, "OTA URL: $otaUrl")
        val csigUrl = resolveUrl(updateInfoUrl, updateInfo.full.locationCsig, false)
        Log.d(TAG, "csig URL: $csigUrl")

        val csigInfo = downloadAndCheckCsig(csigUrl)

        val pfMetadata = csigInfo.getOrThrow(OtaPaths.METADATA_NAME)
        val metadata = downloadAndCheckMetadata(otaUrl, pfMetadata, csigInfo)

        if (metadata.postcondition.buildCount != 1) {
            throw ValidationException("Metadata postcondition lists multiple fingerprints")
        }
        val fingerprint = metadata.postcondition.getBuild(0)
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
            otaUrl,
            csigInfo,
        )
    }

    /** Asynchronously trigger the update_engine payload application. */
    private fun startInstallation(otaUrl: URL, csigInfo: CsigInfo) {
        val pfPayload = csigInfo.getOrThrow(OtaPaths.PAYLOAD_NAME)
        val pfPayloadMetadata = csigInfo.getOrThrow(OtaPaths.PAYLOAD_METADATA_NAME)
        val pfPayloadProperties = csigInfo.getOrThrow(OtaPaths.PAYLOAD_PROPERTIES_NAME)
        val pfCareMap = csigInfo.get(OtaPaths.CARE_MAP_NAME)

        Log.i(TAG, "Downloading payload metadata and checking compatibility")

        downloadAndCheckPayloadMetadata(otaUrl, pfPayloadMetadata)

        Log.i(TAG, "Downloading dm-verity care map file")

        if (pfCareMap != null) {
            downloadCareMap(otaUrl, pfCareMap)
        } else {
            Log.w(TAG, "OTA package does not have a dm-verity care map")
        }

        Log.i(TAG, "Downloading payload properties file")

        val payloadProperties = downloadKeyValueFile(otaUrl, pfPayloadProperties)

        Log.i(TAG, "Passing payload information to update_engine")

        val engineProperties = HashMap(payloadProperties).apply {
            put("NETWORK_ID", network!!.networkHandle.toString())
            put("USER_AGENT", USER_AGENT_UPDATE_ENGINE)

            if (authorization != null) {
                Log.i(TAG, "Passing authorization header to update_engine")
                put("AUTHORIZATION", authorization)
            }

            if (prefs.skipPostInstall) {
                put("RUN_POST_INSTALL", "0")
            }
        }

        updateEngine.applyPayload(
            otaUrl.toString(),
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
                        checkUpdateResult.otaUrl,
                        checkUpdateResult.csigInfo,
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

    class BadFormatException(msg: String, cause: Throwable? = null)
        : Exception(msg, cause)

    class ValidationException(msg: String, cause: Throwable? = null)
        : Exception(msg, cause)

    private data class CheckUpdateResult(
        val updateAvailable: Boolean,
        val fingerprint: String,
        val otaUrl: URL,
        val csigInfo: CsigInfo,
    )

    @Serializable
    private data class PropertyFile(
        val name: String,
        val offset: Long,
        val size: Long,
        val digest: String?,
    ) {
        fun equalsWithoutDigest(other: PropertyFile) =
            name == other.name && offset == other.offset && size == other.size
    }

    @Serializable
    private data class CsigInfo(
        val version: Int,
        val files: List<PropertyFile>,
    ) {
        fun get(name: String) = files.find { it.name == name }

        fun getOrThrow(name: String) = get(name)
            ?: throw ValidationException("Missing property files entry: $name")
    }

    @Serializable
    private data class LocationInfo(
        @SerialName("location_ota")
        val locationOta: String,
        @SerialName("location_csig")
        val locationCsig: String,
    )

    @Serializable
    private data class UpdateInfo(
        val version: Int,
        val full: LocationInfo,
        val incremental: Map<String, LocationInfo> = emptyMap(),
    )

    @Parcelize
    enum class Action : Parcelable {
        CHECK,
        INSTALL,
        REVERT,
    }

    sealed interface Result {
        val isError : Boolean
    }

    data class UpdateAvailable(val fingerprint: String) : Result {
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