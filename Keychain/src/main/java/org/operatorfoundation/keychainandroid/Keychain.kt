package org.operatorfoundation.keychainandroid

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import javax.crypto.KeyAgreement

class Keychain(context: Context)
{
    private val masterKey = MasterKey.Builder(context.applicationContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    val encryptedSharedPreferences = EncryptedSharedPreferences.create(
        context.applicationContext,
        "KeychainEncryptedPreferences",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)

    companion object
    {
        val ecAlgorithm = "EC"
        val ecdhAlgorithm = "ECDH"
        val secp256r1Algorithm = "secp256r1"

        // Keychain format key size in bytes
        val publicKeySize = 66
    }

    fun generateEphemeralKeypair(type: KeyType): KeyPair?
    {
        return try
        {
            when(type)
            {
                KeyType.P256KeyAgreement -> generateP256KeyPair()
                KeyType.P256Signing -> generateP256KeyPair()
            }
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            null
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            null
        }
    }

    fun generateAndSaveKeyPair(label: String, type: KeyType): KeyPair?
    {
        val keyPair = generateEphemeralKeypair(type)

        if (keyPair != null)
        {
            storeKeyPair(keyPair, label)
        }

        return keyPair
    }

    fun retrievePrivateKey(label: String, type: KeyType): PrivateKey?
    {
        val privateKeyString = encryptedSharedPreferences.getString(label+PrivateKey.encryptedPrefsLabel, null)
        if (privateKeyString == null) {
            println("Failed to retrieve a private key from encrypted shared preferences with provided label: $label")
            return null
        }
        println("Retrieved a private key from storage: $privateKeyString")
        val javaPrivateKey = PrivateKey.keychainStringToJavaPrivateKey(privateKeyString)

        val publicKeyString = encryptedSharedPreferences.getString(label+PublicKey.encryptedPrefsLabel, null)
        if (publicKeyString == null) {
            println("Failed to retrieve a public key from encrypted shared preferences with provided label: $label")
            return null
        }
        val javaPublicKey = PublicKey.keychainStringToJavaPublicKey(publicKeyString)

        when (type)
        {
            KeyType.P256KeyAgreement ->
            {
                return PrivateKey.P256KeyAgreement(javaPrivateKey, javaPublicKey)
            }

            KeyType.P256Signing ->
            {
                return PrivateKey.P256Signing(javaPrivateKey, javaPublicKey)
            }
        }
    }

    fun deleteKey(label: String)
    {
        encryptedSharedPreferences
            .edit()
            .remove(label+PrivateKey.encryptedPrefsLabel)
            .remove(label+PublicKey.encryptedPrefsLabel)
            .apply()
    }

    fun retrieveOrGeneratePrivateKey(label: String, type: KeyType): PrivateKey?
    {
        val retrieveResult = retrievePrivateKey(label, type)
        if (retrieveResult != null)
        {
            println("Retrieved a SAVED private key.")
            return  retrieveResult
        }
        else
        {
            println("Generating a NEW private key.")
            val keyPair = generateEphemeralKeypair(type)

            if (keyPair != null)
            {
                storeKeyPair(keyPair, label)
            }

            return keyPair?.privateKey
        }
    }

    fun storeKeyPair(keyPair: KeyPair, label: String): Boolean
    {
        val privateKeyString = keyPair.privateKey.toKeychainString()
        val publicKeyString = keyPair.publicKey.toKeychainString()

        val keysSaved = encryptedSharedPreferences.edit().apply {
            putString(label+PrivateKey.encryptedPrefsLabel, privateKeyString)
            putString(label+PublicKey.encryptedPrefsLabel, publicKeyString)
        }.commit()

        if (keysSaved)
        {
            println("KEYPAIR SAVED")
            println("Saved Private: $privateKeyString")
            println("Saved Public: $publicKeyString")
        }
        else
        {
            println("KEYPAIR NOT SAVED")

        }

        return true
    }

    fun generateP256KeyPair(): KeyPair
    {
        val parameterSpec = ECNamedCurveTable.getParameterSpec(secp256r1Algorithm)
        val keyPairGenerator = KeyPairGenerator.getInstance(ecAlgorithm, BouncyCastleProvider())
        keyPairGenerator.initialize(parameterSpec)
        val javaKeyPair = keyPairGenerator.generateKeyPair()
        println("GENERATED A JAVA KEYPAIR")
        println("Private key encoded is ${javaKeyPair.private.encoded.size} bytes.")
        println("Public key encoded is ${javaKeyPair.public.encoded.size} bytes.")
        val keychainPrivateKey = PrivateKey.P256KeyAgreement(javaKeyPair.private, javaKeyPair.public)
        val keychainPublicKey = PublicKey.P256KeyAgreement(javaKeyPair.public)
        return KeyPair(keychainPrivateKey, keychainPublicKey)
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
                                KeyAgreement.getInstance(ecdhAlgorithm, BouncyCastleProvider())
                            keyAgreement.init(privateKey.javaPrivateKey)
                            keyAgreement.doPhase(publicKey.javaPublicKey, true)
                            val secret = keyAgreement.generateSecret(secp256r1Algorithm)
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
