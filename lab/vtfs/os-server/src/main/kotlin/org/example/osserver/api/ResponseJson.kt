package org.example.osserver.api

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.kotlinModule

object ResponseJson {
    private val mapper: ObjectMapper = ObjectMapper().registerModule(kotlinModule())

    fun ok(value: Boolean): ByteArray =
        mapper.writeValueAsBytes(mapOf("ok" to value))

    fun created(ino: Long): ByteArray =
        mapper.writeValueAsBytes(mapOf("ok" to true, "ino" to ino))

    fun builder(value: Any): ByteArray =
        mapper.writeValueAsBytes(value)
}
