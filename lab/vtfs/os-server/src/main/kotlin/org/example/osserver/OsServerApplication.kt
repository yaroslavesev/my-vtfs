package org.example.osserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class OsServerApplication

fun main(args: Array<String>) {
    runApplication<OsServerApplication>(*args)
}
