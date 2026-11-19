import java.sql.Connection

class VulnerableExample {
    private val token = "demo-kotlin-token-123456789"

    fun search(connection: Connection, userId: String) {
        val query = "SELECT * FROM users WHERE id = " + userId
        connection.createStatement().execute(query)
        Runtime.getRuntime().exec(userId)
    }
}
