import java.sql.Connection;
import java.sql.Statement;

class VulnerableExample {
    private static final String PASSWORD = "demo-password-123456789";

    void findUser(Connection connection, String userId) throws Exception {
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement statement = connection.createStatement();
        statement.execute(query);
        Runtime.getRuntime().exec(userId);
    }
}
