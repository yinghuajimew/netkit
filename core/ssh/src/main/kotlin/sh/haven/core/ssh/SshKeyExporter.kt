package sh.haven.core.ssh

import com.jcraft.jsch.JSch
import com.jcraft.jsch.KeyPair
import java.io.ByteArrayOutputStream

/**
 * Converts stored private key bytes to PEM format for export.
 *
 * Handles three storage formats:
 * - Already PEM/OpenSSH (imported keys): returned as-is
 * - PKCS#8 DER (generated RSA/ECDSA): wrapped via JSch writePrivateKey
 * - Raw 32-byte Ed25519 seed: encoded to OpenSSH format via JSch
 */
object SshKeyExporter {

    fun toPem(privateKeyBytes: ByteArray, keyType: String): ByteArray {
        // If it already looks like a PEM or OpenSSH private key, return as-is
        if (privateKeyBytes.size > 5 && privateKeyBytes[0] == '-'.code.toByte()) {
            return privateKeyBytes
        }

        // Ed25519 raw 32-byte seed → OpenSSH private key format
        if (keyType == "ssh-ed25519" && privateKeyBytes.size == 32) {
            return encodeOpenSshEd25519(privateKeyBytes)
        }

        // PKCS#8 DER (RSA/ECDSA from JCA) → PEM wrapper
        // DER starts with 0x30 (SEQUENCE tag)
        if (privateKeyBytes.isNotEmpty() && privateKeyBytes[0] == 0x30.toByte()) {
            return wrapPkcs8Pem(privateKeyBytes)
        }

        // Try JSch as last resort
        val jsch = JSch()
        val kpair = try {
            KeyPair.load(jsch, privateKeyBytes, null)
        } catch (_: Exception) {
            return privateKeyBytes
        }

        return try {
            val out = ByteArrayOutputStream()
            kpair.writePrivateKey(out)
            out.toByteArray()
        } catch (_: UnsupportedOperationException) {
            privateKeyBytes
        } finally {
            kpair.dispose()
        }
    }

    private fun wrapPkcs8Pem(der: ByteArray): ByteArray {
        val b64 = java.util.Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(der)
        return "-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n".toByteArray()
    }

    /**
     * Encode a raw Ed25519 32-byte private seed into OpenSSH private key format.
     * This produces the same format as `ssh-keygen -t ed25519`.
     */
    private fun encodeOpenSshEd25519(seed: ByteArray): ByteArray {
        // Derive public key from seed using BouncyCastle
        val privParams = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0)
        val pubKey = privParams.generatePublicKey().encoded  // 32 bytes

        val out = ByteArrayOutputStream()

        // OpenSSH private key format (see PROTOCOL.key in OpenSSH source)
        val authMagic = "openssh-key-v1\u0000".toByteArray()
        val cipherName = "none"
        val kdfName = "none"
        val kdfOptions = ByteArray(0)
        val numKeys = 1

        // Public key section
        val pubSection = ByteArrayOutputStream()
        writeString(pubSection, "ssh-ed25519")
        writeBytes(pubSection, pubKey)
        val pubSectionBytes = pubSection.toByteArray()

        // Private key section (unencrypted)
        val privSection = ByteArrayOutputStream()
        // checkint (random, must match)
        val checkInt = (System.nanoTime() and 0xFFFFFFFFL).toInt()
        writeInt(privSection, checkInt)
        writeInt(privSection, checkInt)
        writeString(privSection, "ssh-ed25519")
        writeBytes(privSection, pubKey)
        // Ed25519 "private key" in OpenSSH = seed || pubkey (64 bytes)
        writeBytes(privSection, seed + pubKey)
        writeString(privSection, "") // comment
        // Padding to block size (8 bytes for "none" cipher)
        var padByte = 1
        while (privSection.size() % 8 != 0) {
            privSection.write(padByte++)
        }
        val privSectionBytes = privSection.toByteArray()

        // Assemble the full key
        out.write(authMagic)
        writeString(out, cipherName)
        writeString(out, kdfName)
        writeBytes(out, kdfOptions)
        writeInt(out, numKeys)
        writeBytes(out, pubSectionBytes)
        writeBytes(out, privSectionBytes)

        val blob = out.toByteArray()
        val b64 = java.util.Base64.getMimeEncoder(70, "\n".toByteArray())
            .encodeToString(blob)

        val pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n$b64\n-----END OPENSSH PRIVATE KEY-----\n"
        return pem.toByteArray()
    }

    private fun writeInt(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 24) and 0xFF)
        out.write((value shr 16) and 0xFF)
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeBytes(out: ByteArrayOutputStream, data: ByteArray) {
        writeInt(out, data.size)
        out.write(data)
    }

    private fun writeString(out: ByteArrayOutputStream, str: String) {
        writeBytes(out, str.toByteArray())
    }
}
