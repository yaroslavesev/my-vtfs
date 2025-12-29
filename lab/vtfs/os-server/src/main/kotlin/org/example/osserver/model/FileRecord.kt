package org.example.osserver.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import org.hibernate.annotations.JdbcTypeCode
import jakarta.persistence.Table
import org.hibernate.type.SqlTypes

@Entity
@Table(name = "files")
class FileRecord(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var ino: Long? = null,

    @Column(name = "parent_ino", nullable = false)
    var parentIno: Long = 0,

    @Column(nullable = false)
    var token: String = "",

    @Column(nullable = false)
    var name: String = "",

    @Column(name = "is_dir", nullable = false)
    var isDir: Boolean = false,

    @JdbcTypeCode(SqlTypes.LONGVARBINARY)
    @Column(name = "data", columnDefinition = "bytea")
    var data: ByteArray? = null,
)
