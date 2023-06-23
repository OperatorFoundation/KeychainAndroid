package org.operatorfoundation.keychainandroid

import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.KeyAgreement

class Keychain {
    lateinit var encryptedSharedPreferences: EncryptedSharedPreferences

    fun generateEphemeralKeypair(type: KeyType): KeyPair? {
        return try {
            return if (type == KeyType.P256KeyAgreement) {
                val parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
                val keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
                keyPairGenerator.initialize(parameterSpec)
                val keyPair = keyPairGenerator.generateKeyPair()
                val privateKey = keyPair.private
                val publicKey = keyPair.public
                val keychainPrivateKey = PrivateKey.P256KeyAgreement(privateKey)
                val keychainPublicKey = PublicKey.P256KeyAgreement(publicKey)
                KeyPair(keychainPrivateKey, keychainPublicKey)
            } else {
                println("Unsupported key type.  Returning null.")
                null
            }
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            null
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            null
        }
    }

    fun generateAndSavePrivateKey(label: String, type: KeyType): PrivateKey? {
        return try {
            return if (type == KeyType.P256KeyAgreement) {
                val parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
                val keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
                keyPairGenerator.initialize(parameterSpec)
                val privateKey = keyPairGenerator.generateKeyPair().private
                storePrivateKey(PrivateKey.P256KeyAgreement(privateKey), label)
                PrivateKey.P256KeyAgreement(privateKey)
            } else {
                println("Unsupported key type.  Returning null.")
                null
            }
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            null
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            null
        }
    }

    fun retrievePrivateKey(label: String, type: KeyType): PrivateKey? {
        val privateKeyString = encryptedSharedPreferences.getString(label, null)
        if (privateKeyString == null) {
            println("Could not find private key with provided label: $label")
            return null
        }
        return if (type == KeyType.P256KeyAgreement) {
            val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())
            val privateKeyBytes = Base64.decode(privateKeyString, Base64.DEFAULT)
            val spec = PKCS8EncodedKeySpec(privateKeyBytes)
            val privateKey = keyFactory.generatePrivate(spec)
            PrivateKey.P256KeyAgreement(privateKey)
        } else {
            println("Unsupported key type.  Returning null.")
            null
        }
    }

    fun deleteKey(label: String) {
        encryptedSharedPreferences
            .edit()
            .remove(label)
            .apply()
    }

    fun retrieveOrGeneratePrivateKey(label: String, type: KeyType): PrivateKey? {
        val retrieveResult = retrievePrivateKey(label, type)
        return if (retrieveResult != null) {
            retrieveResult
        } else {
            return if (type == KeyType.P256KeyAgreement) {
                val parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
                val keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
                keyPairGenerator.initialize(parameterSpec)
                val privateKey = keyPairGenerator.generateKeyPair().private
                PrivateKey.P256KeyAgreement(privateKey)
            } else {
                null
            }
        }
    }

    fun storePrivateKey(key: PrivateKey, label: String): Boolean {
        val privateKey = when(key) {
            is PrivateKey.P256KeyAgreement -> key.privateKey
            else -> null
        } ?: return false

        // TODO: Verify that .encoded is correct
        val privateKeyString = Base64.encodeToString(privateKey.encoded, Base64.DEFAULT)
        encryptedSharedPreferences
            .edit()
            .putString(label, privateKeyString)
            .apply()
        return true
    }

    fun ecdh(privateKey: PrivateKey?, publicKey: PublicKey?): SymmetricKey?
    {
        return try
        {
            when(privateKey) {
                is PrivateKey.P256KeyAgreement ->
                    when(publicKey) {
                        is PublicKey.P256KeyAgreement -> {
                            val keyAgreement =
                                KeyAgreement.getInstance("ECDH", BouncyCastleProvider())
                            keyAgreement.init(privateKey.privateKey)
                            keyAgreement.doPhase(publicKey.publicKey, true)
                            val secret = keyAgreement.generateSecret("secp256r1")
                            SymmetricKey(secret)
                        }
                        else -> null
                    }
                else -> null
            }

        }
        catch (e: InvalidKeyException)
        {
            e.printStackTrace()
            null
        }
        catch (e: NoSuchAlgorithmException)
        {
            e.printStackTrace()
            null
        }
    }
}