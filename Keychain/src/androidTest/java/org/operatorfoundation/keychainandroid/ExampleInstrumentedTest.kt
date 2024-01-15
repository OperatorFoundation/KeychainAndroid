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

    val appContext = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun useAppContext() {
        // Context of the app under test.
        assertEquals("org.operatorfoundation.keychainandroid", appContext.packageName)
    }

    @Test
    fun testJSONSerializePublicKey()
    {
        // FIXME: Failing to encode correctly
        val keypair = Keychain(appContext).generateAndSaveKeyPair("keychaintest", KeyType.P256KeyAgreement)
        assertNotNull(keypair)
        val privateKeyA = keypair!!.privateKey

        println("-------------------")
        val publicKeyKeychainStringA = privateKeyA.publicKey.toKeychainString() // Base64 (2 newlines?)
        println("publicKeyKeychainString:")
        println(publicKeyKeychainStringA)

        val publicKeyJsonA = Json.encodeToString(publicKeyKeychainStringA) //JSON
        println("publicKeyJson:")
        println(publicKeyJsonA)
        println("-------------------")

        val decodedKeyA: PublicKey = Json.decodeFromString(publicKeyJsonA) // Public Key
        assert(privateKeyA.publicKey.type == decodedKeyA.type)
        assert(privateKeyA.publicKey.javaPublicKey == decodedKeyA.javaPublicKey)

        val privateKeyB = Keychain(appContext).retrieveOrGeneratePrivateKey("keychaintest", KeyType.P256KeyAgreement)
        assertNotNull(privateKeyB)

        println("-------------------")
        val publicKeyKeychainStringB = privateKeyB!!.publicKey.toKeychainString() // Base64 (2 newlines?)
        println("publicKeyKeychainString:")
        println(publicKeyKeychainStringB)

        val publicKeyJsonB = Json.encodeToString(publicKeyKeychainStringB) //JSON
        println("publicKeyJson:")
        println(publicKeyJsonB)
        println("-------------------")

        val decodedKeyB: PublicKey = Json.decodeFromString(publicKeyJsonB) // Public Key

        assert(privateKeyB.publicKey.type == decodedKeyB.type)
        assert(privateKeyB.publicKey.javaPublicKey == decodedKeyB.javaPublicKey)

        assert(privateKeyA.publicKey.type == privateKeyB.publicKey.type)
        assert(decodedKeyA.type == decodedKeyB.type)
        assert(decodedKeyA.javaPublicKey == decodedKeyB.javaPublicKey)
        assert(privateKeyA.publicKey.javaPublicKey == privateKeyB.publicKey.javaPublicKey)
    }

    @Test
    fun testP256KeyAgreementPublicKeyToString()
    {
        val keyPair = Keychain(appContext).generateEphemeralKeypair(KeyType.P256KeyAgreement)
        Assert.assertNotNull(keyPair)
        val publicKeyString = keyPair!!.publicKey.toString()
        println("PublicKeyString: $publicKeyString")
    }

    @Test
    fun testP256KeyAgreementPrivateKeyToKeychainString()
    {
        val keyPair = Keychain(appContext).generateEphemeralKeypair(KeyType.P256KeyAgreement)
        Assert.assertNotNull(keyPair)
        val privateKeyString = keyPair!!.privateKey.toKeychainString()
        println("privateKeyString: $privateKeyString")
    }

}