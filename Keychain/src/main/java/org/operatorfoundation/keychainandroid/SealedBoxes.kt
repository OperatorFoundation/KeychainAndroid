package org.operatorfoundation.keychainandroid

import android.os.Build
import org.bouncycastle.jcajce.spec.AEADParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.GCMParameterSpec

sealed class SealedBox {
    companion object
    {
        var tagSize = 16
        var tagSizeBits = tagSize * 8
        var lengthWithTagSize = 2 + tagSize
        var maxPayloadSize = 16417
        val handshakeSize = 64
    }

    class AESGCM(val nonce: ByteArray, val key: SymmetricKey, val dataToSeal: ByteArray) {
        val cipherText: ByteArray
        val cipher: Cipher
        init {
            val ivSpec: AlgorithmParameterSpec

            ivSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                AEADParameterSpec(nonce, tagSizeBits)
            } else {
                GCMParameterSpec(tagSizeBits, nonce)
            }

            cipher = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            {
                Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider())
            }
            else
            {
                Cipher.getInstance("AES_256/GCM/NoPadding")
            }

            cipher.init(Cipher.ENCRYPT_MODE, key.secretKey, ivSpec)

            cipherText = cipher.doFinal(dataToSeal)
        }

        fun open(key: SymmetricKey): ByteArray {
            val ivSpec: AlgorithmParameterSpec

            ivSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            {
                AEADParameterSpec(nonce, tagSizeBits)
            }
            else
            {
                GCMParameterSpec(tagSizeBits, nonce)
            }

            cipher.init(Cipher.DECRYPT_MODE, key.secretKey, ivSpec)

            return cipher.doFinal(cipherText)
        }

//        constructor(val data: ByteArray) {
//
//        }
    }


}