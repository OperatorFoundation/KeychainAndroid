package org.operatorfoundation.keychainandroid

import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class ExampleUnitTest {
    @Test
    fun testSerializeKeyPair() {
        val keyPair = Keychain().generateEphemeralKeypair(KeyType.P256KeyAgreement)

        val bos = ByteArrayOutputStream()
        val oos = ObjectOutputStream(bos)
        val bytes = bos.toByteArray()
        val bis = ByteArrayInputStream(bytes)
        val ois = ObjectInputStream(bis)

        oos.writeObject(keyPair!!.publicKey)
        oos.flush()

        val clone = ois.readObject() as PublicKey
        println(clone.encodeToString())
    }

    @Test
    fun testNewDarkStarFormat() {
        val keyHexString = ""
        val keyHex = keyHexString.decodeHex()
        PublicKey.newDarkStarFormat(keyHex)
    }
}