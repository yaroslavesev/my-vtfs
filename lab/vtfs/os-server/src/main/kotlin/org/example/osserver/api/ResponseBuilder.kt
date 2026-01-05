package org.example.osserver.api

import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import java.nio.ByteBuffer
import java.nio.ByteOrder

object ResponseBuilder {
    fun withRetVal(retVal: Long, body: ByteArray = ByteArray(0)): ResponseEntity<ByteArray> {
        val retBuf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(retVal).array()
        val payload = ByteArray(retBuf.size + body.size)
        System.arraycopy(retBuf, 0, payload, 0, retBuf.size)
        System.arraycopy(body, 0, payload, retBuf.size, body.size)

        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .contentLength(payload.size.toLong())
            .body(payload)
    }

    fun rawLong(value: Long): ResponseEntity<ByteArray> {
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .contentLength(buf.size.toLong())
            .body(buf)
    }
}
