package org.operatorfoundation.keychainandroid

//import android.util.Base64
import kotlinx.serialization.Serializable
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.util.encoders.Base64
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.Exception

@Serializable
enum class KeyType(val value: Int)
{
    P256KeyAgreement(2),
    P256Signing(6);

//    Curve25519KeyAgreement(1),
//    P384KeyAgreement(3),
//    P521KeyAgreement(4),
//    Curve25519Signing(5),
//    P384Signing(7),
//    P521Signing(8);

    companion object
    {
        fun fromInt(value: Int): KeyType
        {
            return entries.first { thisKeyType: KeyType ->
                thisKeyType.value == value
            }
        }
    }

    fun toByteArray(): ByteArray
    {
        return byteArrayOf(this.value.toByte())
    }
}

@Serializable
class KeyPair(val privateKey: PrivateKey, val publicKey: PublicKey)

@Serializable
sealed class PrivateKey(val javaPrivateKey: java.security.PrivateKey, val javaPublicKey: java.security.PublicKey)
{
    class P256KeyAgreement(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)
    class P256Signing(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)

//    class Curve25519KeyAgreement(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)
//    class P384KeyAgreement(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)
//    class P521KeyAgreement(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)
//    class Curve25519Signing(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)
//    class P384Signing(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)
//    class P521Signing(privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): PrivateKey(privateKey, publicKey)

    companion object
    {
        val encryptedPrefsLabel = "KeychainPrivateKey"

        fun keychainStringToJavaPrivateKey(keychainString: String): java.security.PrivateKey
        {
            // TODO: Verify that this decoder is compatible with swift base64 encoder
//            val keychainBytes = Base64.decode(keychainString, Base64.DEFAULT)
            val keychainBytes = Base64.decode(keychainString)
            return keychainBytesToJavaPrivateKey(keychainBytes)
        }

        fun keychainBytesToJavaPrivateKey(bytes: ByteArray): java.security.PrivateKey
        {
            val keyFactory = KeyFactory.getInstance(Keychain.ecAlgorithm, BouncyCastleProvider())
            val privateKeyBytes = bytes.sliceArray(1 until bytes.size) // Remove our custom key type byte from the front
            val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)

            return keyFactory.generatePrivate(privateKeySpec)
        }
    }

    val type get() = when(this)
    {
        is P256KeyAgreement -> KeyType.P256KeyAgreement
        is P256Signing -> KeyType.P256Signing
    }

    val publicKey: PublicKey get() = when(this)
    {
        is P256KeyAgreement -> PublicKey.P256KeyAgreement(javaPublicKey)
        is P256Signing -> PublicKey.P256Signing(javaPublicKey)
    }

    fun toJavaKeyString(): String
    {
        val privateKey = this.javaPrivateKey
        val privateKeyBytes = privateKey.encoded
        val privateKeyString = Base64.toBase64String(privateKeyBytes)
        return privateKeyString
    }

    fun toKeychainString(): String
    {
        val keyTypeBytes = this.type.toByteArray()
        val keychainKeyString = Base64.toBase64String(keyTypeBytes + this.javaPrivateKey.encoded)
        return keychainKeyString
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
sealed class PublicKey(val javaPublicKey: java.security.PublicKey)
{
    class P256KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
    {
        constructor(keychainBytes: ByteArray): this(keychainBytesToJavaPublicKey(keychainBytes))
    }

    class P256Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
    {
        constructor(keychainBytes: ByteArray): this(keychainBytesToJavaPublicKey(keychainBytes))
    }

//    class Curve25519KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
//    class P384KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
//    class P521KeyAgreement(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
//    class Curve25519Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
//    class P384Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)
//    class P521Signing(javaPublicKey: java.security.PublicKey): PublicKey(javaPublicKey)


    val data get() = javaPublicKeyToKeychainBytes(this.javaPublicKey, this.type)
    val type get() = when (this)
    {
        is P256KeyAgreement -> KeyType.P256KeyAgreement
        is P256Signing -> KeyType.P256Signing
    }

    companion object
    {
        val encryptedPrefsLabel = "KeychainPublicKey"

        fun new(keychainBytes: ByteArray): PublicKey
        {
            val typeByte = keychainBytes[0]
            val keyType = KeyType.fromInt(typeByte.toInt())

            return when(keyType)
            {
                KeyType.P256KeyAgreement -> P256KeyAgreement(keychainBytes)
                KeyType.P256Signing -> P256Signing(keychainBytes)
            }
        }

        fun new(keychainString: String): PublicKey
        {
            val keychainBytes = Base64.decode(keychainString)
            return new(keychainBytes)
        }

        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun keychainStringToJavaPublicKey(keychainString: String): java.security.PublicKey
        {
            val keychainBytes = Base64.decode(keychainString)

            return keychainBytesToJavaPublicKey(keychainBytes)
        }

        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun keychainBytesToJavaPublicKey(bytes: ByteArray): java.security.PublicKey
        {
            println("bytesToPublicKey bytes: " + bytes.toHex())
            if (bytes.size != Keychain.publicKeySize)
            {
                throw InvalidKeySpecException()
            }

            // TODO: Test for correctness
            val keyFactory = KeyFactory.getInstance(Keychain.ecAlgorithm, BouncyCastleProvider())
            val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec(Keychain.secp256r1Algorithm)
            val keyBytes = bytes.sliceArray(1 until bytes.size) // Remove our custom key type byte from the front
            val point = ecSpec.curve.decodePoint(keyBytes)
            val pubSpec = ECPublicKeySpec(point, ecSpec)

            return keyFactory.generatePublic(pubSpec)
        }

        fun javaPublicKeyToKeychainBytes(pubKey: java.security.PublicKey, keyType: KeyType): ByteArray
        {
            val bcecPublicKey = pubKey as BCECPublicKey
            val point = bcecPublicKey.q
            val encodedPoint = point.getEncoded(false)
//            println("encoded point (as hex): \n${encodedPoint.toHex()}")
            println("encoded point (as Base64): ${org.bouncycastle.util.encoders.Base64.toBase64String(encodedPoint)}")

            val keyTypeBytes = byteArrayOf(keyType.value.toByte())

            // Add our key type to the beginning of the key bytes (without replacing anything)
            val keyBytes = keyTypeBytes + encodedPoint
            println("javaPublicKeyToKeychainBytes result (as Base64): ${org.bouncycastle.util.encoders.Base64.toBase64String(keyBytes)}")

            return keyBytes
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

    fun toKeychainString(): String
    {
        return Base64.toBase64String(this.data)
    }

    // this encodes a public key in a way that can be decoded back into a public key
    fun encodeToString(): String {
        val publicKey = this.javaPublicKey
        val bcecPublicKey = publicKey as BCECPublicKey
        val point = bcecPublicKey.q
        val encodedPoint = point.getEncoded(true)
        val result = ByteArray(33)
        System.arraycopy(encodedPoint, 1, result, 0, 32)
        val encodedString = Base64.toBase64String(result)
        println("PublicKey encodedToString() result: $encodedString")

        return encodedString
    }

    // toString is normally used for debugging.  Call encodeToString for a properly formatted string representation
    override fun toString(): String {
        return encodeToString()
    }
}