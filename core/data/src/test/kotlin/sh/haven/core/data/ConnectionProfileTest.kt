package sh.haven.core.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import sh.haven.core.data.db.entities.ConnectionProfile

class ConnectionProfileTest {

    @Test
    fun `default port is 22`() {
        val profile = ConnectionProfile(
            label = "test",
            host = "example.com",
            username = "user",
        )
        assertEquals(22, profile.port)
    }

    @Test
    fun `default auth type is PASSWORD`() {
        val profile = ConnectionProfile(
            label = "test",
            host = "example.com",
            username = "user",
        )
        assertEquals(ConnectionProfile.AuthType.PASSWORD, profile.authType)
    }

    @Test
    fun `id is auto-generated UUID`() {
        val p1 = ConnectionProfile(label = "a", host = "h", username = "u")
        val p2 = ConnectionProfile(label = "a", host = "h", username = "u")
        assertNotEquals("Each profile should get a unique ID", p1.id, p2.id)
    }

    @Test
    fun `keyId is null by default`() {
        val profile = ConnectionProfile(label = "t", host = "h", username = "u")
        assertNull(profile.keyId)
    }

    @Test
    fun `lastConnected is null by default`() {
        val profile = ConnectionProfile(label = "t", host = "h", username = "u")
        assertNull(profile.lastConnected)
    }

    @Test
    fun `copy preserves id`() {
        val original = ConnectionProfile(label = "a", host = "h", username = "u")
        val copy = original.copy(label = "b")
        assertEquals(original.id, copy.id)
        assertEquals("b", copy.label)
    }

    @Test
    fun `AuthType KEY is distinct from PASSWORD`() {
        assertNotEquals(ConnectionProfile.AuthType.PASSWORD, ConnectionProfile.AuthType.KEY)
    }

    // ---- connectionType computed properties ----

    @Test
    fun `isRdp returns true when connectionType is RDP`() {
        val profile = ConnectionProfile(
            label = "rdp",
            host = "10.0.0.1",
            username = "user",
            connectionType = "RDP",
        )
        assert(profile.isRdp) { "Expected isRdp == true for connectionType=RDP" }
    }

    @Test
    fun `isRdp returns false for SSH connection`() {
        val profile = ConnectionProfile(label = "ssh", host = "h", username = "u")
        assert(!profile.isRdp) { "Expected isRdp == false for default SSH connection" }
    }

    @Test
    fun `isDesktop returns true for VNC connection`() {
        val profile = ConnectionProfile(
            label = "vnc",
            host = "10.0.0.1",
            username = "user",
            connectionType = "VNC",
        )
        assert(profile.isDesktop) { "Expected isDesktop == true for connectionType=VNC" }
    }

    @Test
    fun `isDesktop returns true for RDP connection`() {
        val profile = ConnectionProfile(
            label = "rdp",
            host = "10.0.0.1",
            username = "user",
            connectionType = "RDP",
        )
        assert(profile.isDesktop) { "Expected isDesktop == true for connectionType=RDP" }
    }

    @Test
    fun `isDesktop returns false for SSH connection`() {
        val profile = ConnectionProfile(label = "ssh", host = "h", username = "u")
        assert(!profile.isDesktop) { "Expected isDesktop == false for default SSH connection" }
    }

    // ---- RDP field defaults ----

    @Test
    fun `rdpSshForward defaults to false`() {
        val profile = ConnectionProfile(label = "t", host = "h", username = "u")
        assertEquals(false, profile.rdpSshForward)
    }

    @Test
    fun `rdpPassword defaults to null`() {
        val profile = ConnectionProfile(label = "t", host = "h", username = "u")
        assertNull(profile.rdpPassword)
    }
}
