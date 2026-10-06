package sh.haven.core.ssh

import com.jcraft.jsch.JSch
import com.jcraft.jsch.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec

class SshKeyExporterTest {

    // ---- Ed25519 raw seed (32 bytes) → OpenSSH PEM ----

    private fun generateEd25519Seed(): ByteArray {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        return (kp.private as Ed25519PrivateKeyParameters).encoded // 32-byte seed
    }

    @Test
    fun `toPem with Ed25519 raw seed produces OpenSSH private key`() {
        val seed = generateEd25519Seed()
        val pem = SshKeyExporter.toPem(seed, "ssh-ed25519")
        val pemStr = pem.decodeToString()
        assertTrue(
            "Expected OpenSSH PEM header, got: ${pemStr.take(40)}",
            pemStr.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")
        )
        assertTrue(
            "Expected OpenSSH PEM footer",
            pemStr.trimEnd().endsWith("-----END OPENSSH PRIVATE KEY-----")
        )
    }

    @Test
    fun `toPem with Ed25519 raw seed is loadable by JSch`() {
        val seed = generateEd25519Seed()
        val pem = SshKeyExporter.toPem(seed, "ssh-ed25519")
        val jsch = JSch()
        val kpair = KeyPair.load(jsch, pem, null)
        assertNotNull("JSch should parse the exported PEM", kpair)
        assertEquals("Key type should be ED25519", KeyPair.ED25519, kpair.keyType)
        kpair.dispose()
    }

    @Test
    fun `toPem with Ed25519 raw seed round trips through import`() {
        val seed = generateEd25519Seed()
        val pem = SshKeyExporter.toPem(seed, "ssh-ed25519")
        val imported = SshKeyImporter.import(pem)
        assertEquals("ssh-ed25519", imported.keyType)
        assertTrue(imported.fingerprintSha256.startsWith("SHA256:"))
        assertTrue(imported.publicKeyOpenSsh.startsWith("ssh-ed25519 "))
    }

    // ---- RSA PKCS#8 DER → PEM ----

    private fun generateRsaDer(): ByteArray {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom()) // 2048 for speed in tests
        return kpg.generateKeyPair().private.encoded // PKCS#8 DER
    }

    @Test
    fun `toPem with RSA PKCS8 DER produces PEM`() {
        val der = generateRsaDer()
        val pem = SshKeyExporter.toPem(der, "ssh-rsa")
        val pemStr = pem.decodeToString()
        assertTrue(
            "Expected PEM header, got: ${pemStr.take(40)}",
            pemStr.startsWith("-----BEGIN ")
        )
    }

    @Test
    fun `toPem with RSA PKCS8 DER is loadable by JSch`() {
        val der = generateRsaDer()
        val pem = SshKeyExporter.toPem(der, "ssh-rsa")
        val jsch = JSch()
        val kpair = KeyPair.load(jsch, pem, null)
        assertNotNull("JSch should parse the exported PEM", kpair)
        assertEquals("Key type should be RSA", KeyPair.RSA, kpair.keyType)
        kpair.dispose()
    }

    @Test
    fun `toPem with RSA PKCS8 DER round trips through import`() {
        val der = generateRsaDer()
        val pem = SshKeyExporter.toPem(der, "ssh-rsa")
        val imported = SshKeyImporter.import(pem)
        assertEquals("ssh-rsa", imported.keyType)
        assertTrue(imported.fingerprintSha256.startsWith("SHA256:"))
    }

    // ---- ECDSA PKCS#8 DER → PEM ----

    private fun generateEcdsaDer(): ByteArray {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(384, SecureRandom())
        return kpg.generateKeyPair().private.encoded
    }

    @Test
    fun `toPem with ECDSA PKCS8 DER produces PEM`() {
        val der = generateEcdsaDer()
        val pem = SshKeyExporter.toPem(der, "ecdsa-sha2-nistp384")
        val pemStr = pem.decodeToString()
        assertTrue(
            "Expected PEM header",
            pemStr.startsWith("-----BEGIN ")
        )
    }

    @Test
    fun `toPem with ECDSA PKCS8 DER is loadable by JCA`() {
        val der = generateEcdsaDer()
        val pem = SshKeyExporter.toPem(der, "ecdsa-sha2-nistp384")
        val pemStr = pem.decodeToString()
        // Extract Base64 between PEM headers
        val b64 = pemStr.lines()
            .filter { !it.startsWith("-----") && it.isNotBlank() }
            .joinToString("")
        val decoded = java.util.Base64.getDecoder().decode(b64)
        // Verify JCA can load the PKCS#8 DER
        val kf = KeyFactory.getInstance("EC")
        val key = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(decoded))
        assertNotNull("JCA should parse the exported PKCS#8 PEM", key)
    }

    // ---- passthrough for existing PEM ----

    @Test
    fun `toPem with existing PEM returns bytes unchanged`() {
        val pemStr = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
            QyNTUxOQAAACAGDEAEY/2eTWPYbI21/d13lEIrFjHWa11tKBnYa6M6xgAAAJihYZxQoWGc
            UAAAAAtzc2gtZWQyNTUxOQAAACAGDEAEY/2eTWPYbI21/d13lEIrFjHWa11tKBnYa6M6xg
            AAAEASnxhlh0i/Gz1H26nWiojhTd888E1YQC1hgnYMnaZuuAYMQARj/Z5NY9hsjbX93XeU
            QisWMdZrXW0oGdhrozrGAAAAEGhhdmVuLXRlc3QtcGxhaW4BAgMEBQ==
            -----END OPENSSH PRIVATE KEY-----
        """.trimIndent().toByteArray()
        val result = SshKeyExporter.toPem(pemStr, "ssh-ed25519")
        assertTrue(
            "Existing PEM should be returned unchanged",
            pemStr.contentEquals(result)
        )
    }

    // ---- Ed25519 export → import consistency ----

    @Test
    fun `exported Ed25519 key produces same fingerprint when reimported`() {
        val seed = generateEd25519Seed()
        val pem1 = SshKeyExporter.toPem(seed, "ssh-ed25519")
        val imported1 = SshKeyImporter.import(pem1)

        // Export again from imported bytes (should be passthrough since it's PEM now)
        val pem2 = SshKeyExporter.toPem(imported1.privateKeyBytes, "ssh-ed25519")
        val imported2 = SshKeyImporter.import(pem2)

        assertEquals(
            "Fingerprint should be stable across export/import cycles",
            imported1.fingerprintSha256, imported2.fingerprintSha256
        )
    }
}
