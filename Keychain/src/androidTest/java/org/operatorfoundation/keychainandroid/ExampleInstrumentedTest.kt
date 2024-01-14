package org.operatorfoundation.keychainandroid

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun useAppContext() {
        // Context of the app under test.
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("org.operatorfoundation.keychainandroid", appContext.packageName)
    }

    @Test
    fun testJSONSerializePublicKey()
    {
        // FIXME: Failing to encode correctly
        val keyPair = Keychain().generateEphemeralKeypair(KeyType.P256KeyAgreement)
        assertNotNull(keyPair)

        val publicKeyData = keyPair!!.publicKey.toKeychainString() // Base64 (2 newlines?)

        val publicKeyJson = Json.encodeToString(publicKeyData) //JSON (Too many quotes)

        println("\n--> PublicKey as Json: \n$publicKeyJson")

        val decodedKey: PublicKey = Json.decodeFromString(publicKeyJson) // Public Key
        assert(keyPair.publicKey == decodedKey)
    }

    @Test
    fun testP256KeyAgreementPublicKeyToString()
    {
        val keyPair = Keychain().generateEphemeralKeypair(KeyType.P256KeyAgreement)
        Assert.assertNotNull(keyPair)
        val publicKeyString = keyPair!!.publicKey.toString()
        println("PublicKeyString: $publicKeyString")
    }

    @Test
    fun testP256KeyAgreementPrivateKeyToKeychainString()
    {
        val keyPair = Keychain().generateEphemeralKeypair(KeyType.P256KeyAgreement)
        Assert.assertNotNull(keyPair)
        val privateKeyString = keyPair!!.privateKey.toKeychainString()
        println("privateKeyString: $privateKeyString")
    }
}