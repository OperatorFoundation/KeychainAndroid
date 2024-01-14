package org.operatorfoundation.keychainandroid

import org.junit.Assert
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class ExampleUnitTest {
    @Test
    fun testSerializeKeyPair()
    {
        val keyPair = Keychain().generateEphemeralKeypair(KeyType.P256KeyAgreement)

        Assert.assertNotNull(keyPair)

        val bos = ByteArrayOutputStream()
        val oos = ObjectOutputStream(bos)
        val bytes = bos.toByteArray()
        val bis = ByteArrayInputStream(bytes)
        val ois = ObjectInputStream(bis)

        oos.writeObject(keyPair!!.publicKey)
        oos.flush()

        val clone = ois.readObject() as PublicKey
        println(clone.encodeToString())
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

    @Test
    fun testSignatureTypeFromByteArray()
    {
        val bytes = byteArrayOf(2.toByte())
        val signatureTypeFromData = SignatureType.fromBytes(bytes)
        val signatureTypeControl = SignatureType.P256

        Assert.assertEquals(signatureTypeFromData, signatureTypeControl)
    }
}