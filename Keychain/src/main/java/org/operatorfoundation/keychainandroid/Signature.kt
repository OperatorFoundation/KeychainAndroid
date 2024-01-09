package org.operatorfoundation.keychainandroid

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
sealed class Signature(val data: ByteArray)
{
    class P256(data: ByteArray) : org.operatorfoundation.keychainandroid.Signature(data)
//    class P384(val javaSignature: java.security.Signature) : org.operatorfoundation.keychainandroid.Signature()
//    class P521(val javaSignature: java.security.Signature) : org.operatorfoundation.keychainandroid.Signature()

    val type: SignatureType get()
    {
        when(this) {
            is P256 -> return SignatureType.P256
        }
    }

    val typedData: ByteArray get()
    {
        return type.data + this.data
    }
}