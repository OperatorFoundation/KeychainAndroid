package org.operatorfoundation.keychainandroid

import android.annotation.SuppressLint
import kotlinx.serialization.Serializable
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey

enum class KeyType(val value: Int) {
    Curve25519KeyAgreement(1),
    P256KeyAgreement(2),
    P384KeyAgreement(3),
    P521KeyAgreement(4),

    Curve25519Signing(5),
    P256Signing(6),
    P384Signing(7),
    P521Signing(8)
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
        return bytesToHex(privateKeyBytes)
    }
}

@Serializable
sealed class PublicKey {
    class Curve25519KeyAgreement(val publicKey: java.security.PublicKey): PublicKey()
    class P256KeyAgreement(val publicKey: java.security.PublicKey) : PublicKey()
    class P384KeyAgreement(val publicKey: java.security.PublicKey) : PublicKey()
    class P521KeyAgreement(val publicKey: java.security.PublicKey) : PublicKey()

    class Curve25519Signing(val publicKey: java.security.PublicKey) : PublicKey()
    class P256Signing(val publicKey: java.security.PublicKey) : PublicKey()
    class P384Signing(val publicKey: java.security.PublicKey) : PublicKey()
    class P521Signing(val publicKey: java.security.PublicKey) : PublicKey()

    override fun toString(): String {
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
        System.arraycopy(encodedPoint, 1, result, 0, 33)
        return bytesToHex(result)
    }
}

fun bytesToHex(data: ByteArray): String
{
    val hexArray = "0123456789ABCDEF".toCharArray()

    val hexChars = CharArray(data.size * 2)
    for (j in data.indices) {
        val v = data[j].toInt() and 0xFF

        hexChars[j * 2] = hexArray[v ushr 4]
        hexChars[j * 2 + 1] = hexArray[v and 0x0F]
    }
    return String(hexChars)
}