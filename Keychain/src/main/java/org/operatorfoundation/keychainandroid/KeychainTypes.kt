package org.operatorfoundation.keychainandroid

import android.util.Base64
import kotlinx.serialization.Serializable
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.spec.InvalidKeySpecException
import kotlin.Exception

enum class KeyType(val value: Int) {
    Curve25519KeyAgreement(1),
    P256KeyAgreement(2),
    P384KeyAgreement(3),
    P521KeyAgreement(4),

    Curve25519Signing(5),
    P256Signing(6),
    P384Signing(7),
    P521Signing(8);

    companion object
    {
        fun fromInt(value: Int): KeyType
        {
            return KeyType.values().first { thisKeyType: KeyType ->
                thisKeyType.value == value
            }
        }
    }
}

class KeyPair(val privateKey: PrivateKey, val publicKey: PublicKey)

@Serializable
sealed class PrivateKey(val javaPrivateKey: java.security.PrivateKey)
{
    class Curve25519KeyAgreement(privateKey: java.security.PrivateKey): PrivateKey(privateKey)
    class P256KeyAgreement(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)
    class P384KeyAgreement(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)
    class P521KeyAgreement(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)
    class Curve25519Signing(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)
    class P256Signing(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)
    class P384Signing(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)
    class P521Signing(privateKey: java.security.PrivateKey) : PrivateKey(privateKey)


    override fun toString(): String
    {
        val privateKey = this.javaPrivateKey
        val privateKeyBytes = privateKey.encoded
        return Base64.encodeToString(privateKeyBytes, Base64.DEFAULT)
    }

    fun signatureForData(data: ByteArray): org.operatorfoundation.keychainandroid.Signature
    {
        val privateKey = this.javaPrivateKey
        val signer = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider())
        signer.initSign(privateKey)
        signer.update(data)
        val signedData = signer.sign()

        when(this)
        {
            is P256Signing -> return org.operatorfoundation.keychainandroid.Signature.P256(signedData)
            else -> throw Exception("This key type does not support signing.")
        }
    }
}

@Serializable(with = PublicKeyAsStringSerializer::class)
sealed class PublicKey(val javaPublicKey: java.security.PublicKey) {
    val data get() = when(this) {
        is P256KeyAgreement -> javaPublicKeyToKeychainBytes(this.javaPublicKey)
        else -> null
    }

    class Curve25519KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    class P256KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey) {
        constructor(data: ByteArray): this(keychainBytesToJavaPublicKey(data))
    }

    class P384KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    class P521KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    class Curve25519Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    class P256Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    class P384Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    class P521Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)

    companion object
    {
        val x936FormatByte: Byte = 3
        fun new(typedData: ByteArray): PublicKey
        {
            val typeByte = typedData[0]
            val keyType = KeyType.fromInt(typeByte.toInt())
            when(keyType) {
                KeyType.P256KeyAgreement -> return P256KeyAgreement(typedData)
                else -> throw Exception("Unsupported KeyType")
            }
        }

        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun keychainBytesToJavaPublicKey(bytes: ByteArray): java.security.PublicKey
        {
            println("bytesToPublicKey bytes: " + bytes.toHex())
            if (bytes.size != 66) // This is the 33 byte key with a [0] notating the key's type and [1..] being the 32 byte key
            {
                throw InvalidKeySpecException()
            }

            val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())
            val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
            val keyBytes = bytes.sliceArray(1 until bytes.size) // Remove our custom key type byte from the front
            val point = ecSpec.curve.decodePoint(keyBytes)
            val pubSpec = ECPublicKeySpec(point, ecSpec)

            return keyFactory.generatePublic(pubSpec)
        }

        fun javaPublicKeyToKeychainBytes(pubKey: java.security.PublicKey?): ByteArray {
            val bcecPublicKey = pubKey as BCECPublicKey
            val point = bcecPublicKey.q
            val encodedPoint = point.getEncoded(false)
            println("encoded point hex: ${encodedPoint.toHex()}")

            val keyType = byteArrayOf(KeyType.P256KeyAgreement.value.toByte())
            println("adding identifier byte to key!")

            // Add our key type to the beginning of the key bytes (without replacing anything)
            return keyType + encodedPoint
        }
    }

    fun isValidSignature(signature: org.operatorfoundation.keychainandroid.Signature, dataToVerify: ByteArray): Boolean
    {
        val signatureData = when(signature)
        {
            is org.operatorfoundation.keychainandroid.Signature.P256 -> this.data
        }

        val javaPublicKey = this.javaPublicKey
        val signer = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider())
        signer.initVerify(javaPublicKey)
        signer.update(dataToVerify)

        return signer.verify(signatureData)
    }

    // this encodes a public key in a way that can be decoded back into a public key
    fun encodeToString(): String {
        val publicKey = this.javaPublicKey
        val bcecPublicKey = publicKey as BCECPublicKey
        val point = bcecPublicKey.q
        val encodedPoint = point.getEncoded(true)
        val result = ByteArray(33)
        System.arraycopy(encodedPoint, 1, result, 0, 32)
        return Base64.encodeToString(result, Base64.DEFAULT)
    }

    // toString is normally used for debugging.  Call encodeToString for a properly formatted string representation
    override fun toString(): String {
        return encodeToString()
    }
}