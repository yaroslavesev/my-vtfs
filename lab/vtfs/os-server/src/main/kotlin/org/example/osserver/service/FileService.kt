package org.example.osserver.service

import org.example.osserver.model.FileRecord
import org.example.osserver.repository.FileRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class FileService(
    private val repository: FileRepository,
) {
    @Transactional(readOnly = true)
    fun findByParent(parentIno: Long, token: String): List<FileRecord> =
        repository.findAllByParentInoAndToken(parentIno, token)

    @Transactional(readOnly = true)
    fun findByParentAndName(parentIno: Long, token: String, name: String): FileRecord? =
        repository.findByParentInoAndTokenAndName(parentIno, token, name)

    @Transactional
    fun create(token: String, parentIno: Long, isDir: Boolean, data: ByteArray?, name: String): FileRecord {
        val record = FileRecord(
            parentIno = parentIno,
            token = token,
            name = name,
            isDir = isDir,
            data = data,
        )
        return repository.save(record)
    }

    @Transactional
    fun update(token: String, parentIno: Long, name: String, data: ByteArray?): Boolean {
        val record = repository.findByParentInoAndTokenAndName(parentIno, token, name) ?: return false
        if (data != null) record.data = data
        repository.save(record)
        return true
    }

    @Transactional
    fun delete(token: String, parentIno: Long, name: String): Boolean =
        repository.deleteByTokenAndParentInoAndName(token, parentIno, name) > 0

    @Transactional
    fun rmdir(token: String, parentIno: Long, name: String): Long {
        val rec = repository.findByParentInoAndTokenAndName(parentIno, token, name) ?: return -2
        if (!rec.isDir) return -2

        val ino = rec.ino ?: return -1

        if (repository.existsByTokenAndParentIno(token, ino)) return -39

        repository.delete(rec)
        return 0
    }

}
