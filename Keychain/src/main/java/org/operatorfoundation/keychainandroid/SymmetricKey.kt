package org.operatorfoundation.keychainandroid

import kotlinx.serialization.Serializable
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@Serializable
class SymmetricKey(val secretKey: SecretKey) {
    constructor(data: ByteArray): this(SymmetricKey.bytesToSecretKey(data))
    val data get() = SymmetricKey.secretKeyToBytes(secretKey)

    companion object {
        fun bytesToSecretKey(data: ByteArray): SecretKey {
            return SecretKeySpec(data, "AES")
        }

        fun secretKeyToBytes(secretKey: SecretKey): ByteArray {
            return secretKey.encoded
        }
    }
}