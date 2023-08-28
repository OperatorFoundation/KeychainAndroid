package org.operatorfoundation.keychainandroid
fun ByteArray.toHex(): String = joinToString(separator = "") {
        eachByte -> "%02x".format(eachByte)
}

