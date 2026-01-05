package org.example.osserver.api.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class FileListItem(
    val ino: Long,
    val name: String,
    @JsonProperty("is_dir")
    val isDir: Boolean,
)
