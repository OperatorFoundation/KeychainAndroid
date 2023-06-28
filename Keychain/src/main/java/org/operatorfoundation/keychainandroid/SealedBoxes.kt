package org.operatorfoundation.keychainandroid

import android.os.Build
import org.bouncycastle.jcajce.spec.AEADParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.GCMParameterSpec

enum class SealedBoxType(val value: Int) {
    AESGCM(2)
}

sealed class SealedBox {
    companion object {
        var tagSize = 16
        var tagSizeBits = tagSize * 8
        var lengthWithTagSize = 2 + tagSize
        var maxPayloadSize = 16417
        val handshakeSize = 64

        fun seal(typeSelector: SealedBoxType, key: SymmetricKey, nonce: ByteArray, plaintext: ByteArray) : ByteArray
        {
            val result = when (typeSelector) {
                SealedBoxType.AESGCM -> return AESGCM.seal(nonce, key, plaintext)
            }

            return result
        }

        fun open(typeSelector: SealedBoxType, key: SymmetricKey, nonce: ByteArray, ciphertext: ByteArray) : ByteArray
        {
            val result = when (typeSelector) {
                SealedBoxType.AESGCM -> return AESGCM.open(nonce, key, ciphertext)
            }

            return result
        }
    }

    class AESGCM(val nonce: ByteArray, val key: SymmetricKey, val ciphertext: ByteArray): SealedBox() {
        companion object {
            fun seal(nonce: ByteArray, key: SymmetricKey, dataToSeal: ByteArray): ByteArray {
                val ivSpec: AlgorithmParameterSpec

                ivSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                    AEADParameterSpec(nonce, tagSizeBits)
                } else {
                    GCMParameterSpec(tagSizeBits, nonce)
                }

                lateinit var cipher: Cipher

                cipher = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
                {
                    Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider())
                }
                else
                {
                    Cipher.getInstance("AES_256/GCM/NoPadding")
                }
                cipher.init(Cipher.ENCRYPT_MODE, key.secretKey, ivSpec)

                val ciphertext = cipher.doFinal(dataToSeal)

                return ciphertext
            }

            fun open(nonce: ByteArray, key: SymmetricKey, ciphertext: ByteArray): ByteArray {
                val ivSpec: AlgorithmParameterSpec

                ivSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
                {
                    AEADParameterSpec(nonce, tagSizeBits)
                }
                else
                {
                    GCMParameterSpec(tagSizeBits, nonce)
                }

                lateinit var cipher: Cipher

                cipher = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
                {
                    Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider())
                }
                else
                {
                    Cipher.getInstance("AES_256/GCM/NoPadding")
                }
                cipher.init(Cipher.DECRYPT_MODE, key.secretKey, ivSpec)

                return cipher.doFinal(ciphertext)
            }
        }

//        constructor(val data: ByteArray) {
//
//        }
    }


}