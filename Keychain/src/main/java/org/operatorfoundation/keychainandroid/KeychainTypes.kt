package org.operatorfoundation.keychainandroid

import android.util.Base64
import kotlinx.serialization.Serializable
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.lang.Exception
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException

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
sealed class PrivateKey {

    class Curve25519KeyAgreement(val privateKey: java.security.PrivateKey): PrivateKey()

    class P256KeyAgreement(val privateKey: java.security.PrivateKey) : PrivateKey()

    class P384KeyAgreement(val privateKey: java.security.PrivateKey) : PrivateKey()

    class P521KeyAgreement(val privateKey: java.security.PrivateKey) : PrivateKey()

    class Curve25519Signing(val privateKey: java.security.PrivateKey) : PrivateKey()

    class P256Signing(val privateKey: java.security.PrivateKey) : PrivateKey()

    class P384Signing(val privateKey: java.security.PrivateKey) : PrivateKey()
    
    class P521Signing(val privateKey: java.security.PrivateKey) : PrivateKey()

    override fun toString(): String {
        val privateKey = when(this) {
            is P256KeyAgreement -> this.privateKey
            else -> null
        }

        if (privateKey == null) {
            println("error: invalid key type.")
            return ""
        }

            val privateKeyBytes = privateKey.encoded
            return Base64.encodeToString(privateKeyBytes, Base64.DEFAULT)
        }
}

@Serializable(with = PublicKeyAsStringSerializer::class)
sealed class PublicKey {
    val data get() = when(this) {
        is P256KeyAgreement -> javaPublicKeyToKeychainBytes(this.javaPublicKey)
        else -> null
    }

    class Curve25519KeyAgreement(val javaPublicKey: java.security.PublicKey): PublicKey()

    class P256KeyAgreement(val javaPublicKey: java.security.PublicKey) : PublicKey() {
        constructor(data: ByteArray): this(keychainBytesToJavaPublicKey(data))
    }

    class P384KeyAgreement(val javaPublicKey: java.security.PublicKey) : PublicKey()

    class P521KeyAgreement(val javaPublicKey: java.security.PublicKey) : PublicKey()

    class Curve25519Signing(val javaPublicKey: java.security.PublicKey) : PublicKey()

    class P256Signing(val javaPublicKey: java.security.PublicKey) : PublicKey()

    class P384Signing(val javaPublicKey: java.security.PublicKey) : PublicKey()

    class P521Signing(val javaPublicKey: java.security.PublicKey) : PublicKey()

    companion object {
        val x936FormatByte: Byte = 3
        fun new(typedData: ByteArray): org.operatorfoundation.keychainandroid.PublicKey {
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

    // this encodes a public key in a way that can be decoded back into a public key
    fun encodeToString(): String {
        val publicKey = when(this) {
            is P256KeyAgreement -> this.javaPublicKey
            else -> null
        }
        if (publicKey == null) {
            println("error: invalid key type.")
            return ""
        }

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

//fun bytesToHex(data: ByteArray): String
//{
//    val hexArray = "0123456789ABCDEF".toCharArray()
//
//    val hexChars = CharArray(data.size * 2)
//    for (j in data.indices) {
//        val v = data[j].toInt() and 0xFF
//
//        hexChars[j * 2] = hexArray[v ushr 4]
//        hexChars[j * 2 + 1] = hexArray[v and 0x0F]
//    }
//    return String(hexChars)
//}