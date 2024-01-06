package org.operatorfoundation.keychainandroid

import java.security.Security

enum class SignatureType(val value: Int)
{
    P256(2),
    P384(3),
    P521(5);

    val data: ByteArray get()
    {
        return byteArrayOf(this.value.toByte())
    }

    companion object
    {
        fun fromInt(value: Int): SignatureType
        {
            return SignatureType.values().first { thisSignatureType: SignatureType ->
                thisSignatureType.value == value
            }
        }

        fun fromBytes(data: ByteArray): SignatureType?
        {
            if (data.size != 1)
            {
                return null
            }

            val byteAsInt = data.first().toInt()
            return SignatureType.fromInt(byteAsInt)
        }
    }
}
sealed class Signature(val javaSignature: java.security.Signature)
{
    val type: SignatureType get()
    {
        TODO("Not yet implemented")
        throw Exception("Not yet implemented")
//        when(javaSignature.algorithm){
//        }
    }
//    abstract fun type(): SignatureType
//    abstract fun data(): ByteArray
}