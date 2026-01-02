package org.example.osserver.repository

import org.example.osserver.model.FileRecord
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface FileRepository : JpaRepository<FileRecord, Long> {
    fun findAllByParentInoAndToken(parentIno: Long, token: String): List<FileRecord>

    fun findByParentInoAndTokenAndName(parentIno: Long, token: String, name: String): FileRecord?

    @Modifying
    @Query("delete from FileRecord f where f.token = :token and f.parentIno = :parentIno and f.name = :name")
    fun deleteByTokenAndParentInoAndName(
        @Param("token") token: String,
        @Param("parentIno") parentIno: Long,
        @Param("name") name: String,
    ): Int

    fun existsByTokenAndParentIno(token: String, parentIno: Long): Boolean
}
