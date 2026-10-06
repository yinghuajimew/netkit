package sh.haven.core.fido

import android.app.Activity
import android.util.Log
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "FidoAuthenticator"

data class FidoAssertionResult(
    val signature: ByteArray,
    val flags: Byte,
    val counter: Int,
)

/**
 * Manages FIDO2 authenticator interactions via yubikit.
 * Handles USB and NFC connections to security keys.
 */
@Singleton
class FidoAuthenticator @Inject constructor(
    @ApplicationContext private val context: android.content.Context,
) {
    private var yubikitManager: YubiKitManager? = null
    private var pendingDevice: CompletableDeferred<YubiKeyDevice>? = null

    /** Callback for UI to show/hide "touch your security key" prompt. */
    var onTouchRequired: ((Boolean) -> Unit)? = null

    fun startUsbDiscovery(activity: Activity) {
        val manager = YubiKitManager(context)
        yubikitManager = manager
        Log.d(TAG, "Starting USB discovery")
        manager.startUsbDiscovery(UsbConfiguration()) { device ->
            Log.d(TAG, "USB YubiKey connected: ${device.usbDevice.productName}")
            pendingDevice?.complete(device)
        }
    }

    fun startNfcDiscovery(activity: Activity) {
        val manager = yubikitManager ?: YubiKitManager(context).also { yubikitManager = it }
        try {
            Log.d(TAG, "Starting NFC discovery")
            manager.startNfcDiscovery(NfcConfiguration(), activity) { device ->
                Log.d(TAG, "NFC YubiKey tapped")
                pendingDevice?.complete(device)
            }
        } catch (e: NfcNotAvailable) {
            Log.w(TAG, "NFC not available: ${e.message}")
        }
    }

    fun stopDiscovery(activity: Activity) {
        try {
            yubikitManager?.stopUsbDiscovery()
            yubikitManager?.stopNfcDiscovery(activity)
        } catch (_: Exception) {}
    }

    /**
     * Perform a FIDO2 assertion. Blocks until a security key is connected/tapped
     * and the user touches it.
     *
     * @param rpId       The relying party ID (application string, e.g. "ssh:")
     * @param message    The SSH sign data to hash and sign
     * @param credentialId The credential ID (key_handle) from the SK key file
     * @return The assertion result with signature, flags, and counter
     */
    suspend fun getAssertion(
        rpId: String,
        message: ByteArray,
        credentialId: ByteArray,
    ): FidoAssertionResult = withContext(Dispatchers.IO) {
        Log.d(TAG, "FIDO2 assertion requested: rpId=$rpId, message=${message.size}b, credId=${credentialId.size}b")

        // SHA-256 hash the SSH sign data to get clientDataHash
        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(message)
        Log.d(TAG, "clientDataHash: ${clientDataHash.size} bytes")

        onTouchRequired?.invoke(true)

        try {
            // Wait for a YubiKey to be connected
            val deferred = CompletableDeferred<YubiKeyDevice>()
            pendingDevice = deferred
            Log.d(TAG, "Waiting for security key (USB or NFC)...")

            val device = deferred.await()
            Log.d(TAG, "Security key connected, opening CTAP2 session")

            val result = performAssertion(device, rpId, clientDataHash, credentialId)

            Log.d(TAG, "FIDO2 assertion success: sig=${result.signature.size}b, flags=0x${
                "%02x".format(result.flags)
            }, counter=${result.counter}")

            result
        } finally {
            pendingDevice = null
            onTouchRequired?.invoke(false)
        }
    }

    private fun performAssertion(
        device: YubiKeyDevice,
        rpId: String,
        clientDataHash: ByteArray,
        credentialId: ByteArray,
    ): FidoAssertionResult {
        device.openConnection(SmartCardConnection::class.java).use { connection ->
            val ctap = Ctap2Session(connection)
            Log.d(TAG, "CTAP2 session opened, requesting assertion")
            Log.d(TAG, "  rpId: $rpId")
            Log.d(TAG, "  clientDataHash: ${clientDataHash.size} bytes")
            Log.d(TAG, "  credentialId: ${credentialId.size} bytes")

            // Build allow list with our credential ID
            val allowList = listOf(
                mapOf<String, Any>(
                    "type" to "public-key",
                    "id" to credentialId,
                )
            )

            val options = mapOf<String, Any>("up" to true) // require user presence (touch)

            Log.d(TAG, "Calling ctap.getAssertions()...")
            val assertions = ctap.getAssertions(
                rpId,
                clientDataHash,
                allowList,
                null, // extensions
                options,
                null, // pinUvAuthParam
                null, // pinUvAuthProtocol
                null, // commandState
            )

            require(assertions.isNotEmpty()) { "No assertions returned from authenticator" }
            val assertion = assertions[0]
            Log.d(TAG, "Got ${assertions.size} assertion(s)")

            // Parse authenticatorData: rpIdHash(32) || flags(1) || counter(4)
            val authData = assertion.authenticatorData
            Log.d(TAG, "authenticatorData: ${authData.size} bytes")
            require(authData.size >= 37) { "authenticatorData too short: ${authData.size}" }
            val flags = authData[32]
            val counter = ((authData[33].toInt() and 0xFF) shl 24) or
                ((authData[34].toInt() and 0xFF) shl 16) or
                ((authData[35].toInt() and 0xFF) shl 8) or
                (authData[36].toInt() and 0xFF)

            val signature = assertion.signature
            Log.d(TAG, "Raw signature: ${signature.size} bytes, flags=0x${"%02x".format(flags)}, counter=$counter")

            return FidoAssertionResult(
                signature = signature,
                flags = flags,
                counter = counter,
            )
        }
    }
}
