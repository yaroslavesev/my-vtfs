package org.example.osserver.api

import org.example.osserver.api.dto.FileListItem
import org.example.osserver.service.FileService
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class FileController(
    private val service: FileService,
) {
    private val logger = LoggerFactory.getLogger(FileController::class.java)

    @GetMapping("/list")
    fun list(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
    ): ResponseEntity<ByteArray> {
        logger.info("[list] Incoming request token={} parent_ino={}", token, parentIno)
        val files = service.findByParent(parentIno, token)
        val response = files.map { FileListItem(it.ino ?: 0, it.name, it.isDir) }
        logger.info("[list] Sending response {}", response)
        val json = ResponseJson.builder(response)
        return ResponseBuilder.withRetVal(0, json)
    }

    @GetMapping("/read")
    fun read(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
        @RequestParam(name = "name") name: String,
    ): ResponseEntity<ByteArray> {
        logger.info("[read] Incoming request token={} parent_ino={} name={}", token, parentIno, name)
        val file = service.findByParentAndName(parentIno, token, name)
        if (file == null) {
            logger.info("[read] File not found")
            return ResponseBuilder.withRetVal(-1, "File not found".toByteArray(Charsets.UTF_8))
        }

        val body = file.data ?: ByteArray(0)
        return ResponseBuilder.withRetVal(0, body)
    }

    @GetMapping("/create")
    fun create(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
        @RequestParam(name = "name") name: String,
        @RequestParam(name = "data", required = false) data: String?,
    ): ResponseEntity<ByteArray> {
        val content = (data ?: "").toByteArray(Charsets.UTF_8)
        logger.info("[create] Incoming request token={} parent_ino={} name={} dataLength={}", token, parentIno, name, content.size)

        val existing = service.findByParentAndName(parentIno, token, name)
        if (existing != null) {
            val payload = ResponseJson.ok(false)
            return ResponseBuilder.withRetVal(-1, payload)
        }

        val created = service.create(token, parentIno, false, content, name)
        val ino = created.ino ?: 0L
        val payload = ResponseJson.created(ino)
        return ResponseBuilder.withRetVal(0, payload)
    }

    @GetMapping("/write")
    fun write(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
        @RequestParam(name = "name") name: String,
        @RequestParam(name = "data", required = false) data: String?,
    ): ResponseEntity<ByteArray> {
        val content = (data ?: "").toByteArray(Charsets.UTF_8)
        logger.info("[write] Incoming request token={} parent_ino={} name={} dataLength={}", token, parentIno, name, content.size)

        val success = service.update(token, parentIno, name, content)
        val payload = ResponseJson.ok(success)
        return ResponseBuilder.withRetVal(if (success) 0 else -1, payload)
    }

    @GetMapping("/mkdir")
    fun mkdir(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
        @RequestParam(name = "name") name: String,
    ): ResponseEntity<ByteArray> {
        logger.info("[mkdir] Incoming request token={} parent_ino={} name={}", token, parentIno, name)
        val existing = service.findByParentAndName(parentIno, token, name)
        if (existing != null) {
            return ResponseBuilder.withRetVal(-1, ResponseJson.ok(false))
        }
        val created = service.create(token, parentIno, true, null, name)
        val ino = created.ino ?: 0L
        return ResponseBuilder.withRetVal(0, ResponseJson.created(ino))
    }

    @GetMapping("/unlink")
    fun unlink(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
        @RequestParam(name = "name") name: String,
    ): ResponseEntity<ByteArray> {
        logger.info("[unlink] Incoming request token={} parent_ino={} name={}", token, parentIno, name)
        val success = service.delete(token, parentIno, name)
        val payload = ResponseJson.ok(success)
        return ResponseBuilder.withRetVal(if (success) 0 else -1, payload)
    }

    @GetMapping("/rmdir")
    fun rmdir(
        @RequestParam(name = "token", defaultValue = "") token: String,
        @RequestParam(name = "parent_ino", defaultValue = "0") parentIno: Long,
        @RequestParam(name = "name") name: String,
    ): ResponseEntity<ByteArray> {
        logger.info("[rmdir] Incoming request token={} parent_ino={} name={}", token, parentIno, name)

        val ret = service.rmdir(token, parentIno, name)
        val payload = ResponseJson.ok(ret == 0L)

        return ResponseBuilder.withRetVal(ret, payload)
    }
}
