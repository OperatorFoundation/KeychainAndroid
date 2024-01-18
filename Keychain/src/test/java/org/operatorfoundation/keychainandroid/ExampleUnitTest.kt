package org.operatorfoundation.keychainandroid

import org.bouncycastle.util.encoders.Base64
import org.junit.Assert
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class ExampleUnitTest
{
    @Test
    fun testSignatureTypeFromByteArray()
    {
        val bytes = byteArrayOf(2.toByte())
        val signatureTypeFromData = SignatureType.fromBytes(bytes)
        val signatureTypeControl = SignatureType.P256

        Assert.assertEquals(signatureTypeFromData, signatureTypeControl)
    }

    @Test
    fun testBase64EncodingSwiftCompatibility()
    {
        val swiftBase64String = "AgIC"
        val bytes = byteArrayOf(2, 2, 2)
        val base64String = Base64.toBase64String(bytes)

        println("base64String: $base64String")

        assert(swiftBase64String == base64String)
    }

    @Test
    fun testKeychainPublicKeySwiftCompatibility()
    {
        val swiftPublicKeyKeychainString = "AgT6QS816nOuLbY96P+yznkZ8ZJQGzlAXTQOp4cJjzounSGBdS6YnoNhyuLnrdpRURExpKCZ+KfXptYZPo8ANL+D"
        val keychainPublicKey = PublicKey.new(swiftPublicKeyKeychainString)
    }
}