package org.operatorfoundation.keychainandroid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import android.util.Base64

object PublicKeyAsStringSerializer : KSerializer<PublicKey> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("PublicKey", PrimitiveKind.STRING)

    // make value into string
    override fun serialize(encoder: Encoder, value: PublicKey) {
        val string = value.encodeToString()
        encoder.encodeString(string)
    }

    // make string into value
    override fun deserialize(decoder: Decoder): PublicKey {
        val string = decoder.decodeString()
        val bytes = Base64.decode(string, Base64.DEFAULT)

        return PublicKey.new(bytes)
    }
}