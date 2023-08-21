package org.operatorfoundation.keychainandroid

import android.util.Base64
import kotlinx.serialization.Serializable
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.lang.Error
import java.lang.Exception
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.sql.Types

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
        is P256KeyAgreement -> publicKeyToBytes(this.publicKey)
        else -> null
    }

    class Curve25519KeyAgreement(val publicKey: java.security.PublicKey): PublicKey()

    class P256KeyAgreement(val publicKey: java.security.PublicKey) : PublicKey() {
        constructor(data: ByteArray): this(bytesToPublicKey(data))
    }

    class P384KeyAgreement(val publicKey: java.security.PublicKey) : PublicKey()

    class P521KeyAgreement(val publicKey: java.security.PublicKey) : PublicKey()

    class Curve25519Signing(val publicKey: java.security.PublicKey) : PublicKey()

    class P256Signing(val publicKey: java.security.PublicKey) : PublicKey()

    class P384Signing(val publicKey: java.security.PublicKey) : PublicKey()

    class P521Signing(val publicKey: java.security.PublicKey) : PublicKey()

    companion object {
        fun new(typedData: ByteArray): PublicKey {
            val typeByte = typedData[0]
            val keyType = KeyType.fromInt(typeByte.toInt())
            when(keyType) {
                KeyType.P256KeyAgreement -> return P256KeyAgreement(bytesToPublicKey(typedData))
                else -> throw Exception("Unsupported KeyType")
            }
        }

        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun bytesToPublicKey(bytes: ByteArray): java.security.PublicKey
        {
            if (bytes.size != 33) // This is the 33 byte key with a [0] notating the key's type and [1..] being the 32 byte key
            {
                throw InvalidKeySpecException()
            }

            val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())
            val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
            val encodedPoint = ByteArray(33)
            System.arraycopy(bytes, 0, encodedPoint, 1, 32)
            encodedPoint[0] = 3
            val point = ecSpec.curve.decodePoint(encodedPoint)
            val pubSpec = ECPublicKeySpec(point, ecSpec)

            return keyFactory.generatePublic(pubSpec)
        }

        fun bytesToPublicKeyDarkstarFormat(bytes: ByteArray): PublicKey {
            if (bytes.size != 32)
            {
                throw InvalidKeySpecException()
            }

            val buffer = ByteArray(33)
            System.arraycopy(bytes, 0, buffer, 1, 32)
            buffer[0] = KeyType.P256KeyAgreement.value.toByte()

            return P256KeyAgreement(bytesToPublicKey(buffer))
        }

        fun publicKeyToBytes(pubKey: java.security.PublicKey?): ByteArray {
            val bcecPublicKey = pubKey as BCECPublicKey
            val point = bcecPublicKey.q
            val encodedPoint = point.getEncoded(true)
            val result = ByteArray(33)
            System.arraycopy(encodedPoint, 1, result, 1, 32)
            result[0] = KeyType.P256KeyAgreement.value.toByte()

            return result
        }

        fun publicKeyToBytesDarkstarFormat(pubKey: PublicKey): ByteArray {
            val keyBytes = pubKey.data
            if (keyBytes == null) {
                throw Exception("wrong key type.  Expected P256KeyAgreement")
            }

            val result = ByteArray(32)
            System.arraycopy(keyBytes, 1, result, 0, 32)

            return result
        }
    }

    // this encodes a public key in a way that can be decoded back into a public key
    fun encodeToString(): String {
        val publicKey = when(this) {
            is P256KeyAgreement -> this.publicKey
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