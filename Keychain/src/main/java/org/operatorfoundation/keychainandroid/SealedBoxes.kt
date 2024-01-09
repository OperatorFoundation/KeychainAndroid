package org.operatorfoundation.keychainandroid

import android.os.Build
import org.bouncycastle.jcajce.spec.AEADParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

enum class SealedBoxType(val value: Int) {
    AESGCM(2)
}

sealed class SealedBox
{
    companion object
    {
        var tagSize = 16
        var tagSizeBits = tagSize * 8
    }

    class AESGCM(): SealedBox()
    {
        var cipher: Cipher

        init
        {
            cipher = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            {
                Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider())
            }
            else
            {
                Cipher.getInstance("AES_256/GCM/NoPadding")
            }
        }

        fun seal(nonce: ByteArray, key: SymmetricKey, dataToSeal: ByteArray): ByteArray
        {
            val ivSpec: AlgorithmParameterSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            {
                AEADParameterSpec(nonce, tagSizeBits)
            }
            else
            {
                GCMParameterSpec(tagSizeBits, nonce)
            }

            cipher.init(Cipher.ENCRYPT_MODE, key.secretKey, ivSpec)

            val ciphertext = cipher.doFinal(dataToSeal)

            return ciphertext
        }

        fun open(nonce: ByteArray, key: SymmetricKey, ciphertext: ByteArray): ByteArray {

            val ivSpec: AlgorithmParameterSpec = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P)
            {
                AEADParameterSpec(nonce, tagSizeBits)
            }
            else
            {
                GCMParameterSpec(tagSizeBits, nonce)
            }

            cipher.init(Cipher.DECRYPT_MODE, key.secretKey, ivSpec)

            return cipher.doFinal(ciphertext)
        }
    }


}