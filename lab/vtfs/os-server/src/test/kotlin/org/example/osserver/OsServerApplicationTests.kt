package org.example.osserver

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@Disabled("Интеграционный тест требует живой БД, отключаем по умолчанию")
@SpringBootTest
class OsServerApplicationTests {

    @Test
    fun contextLoads() {
    }
}
