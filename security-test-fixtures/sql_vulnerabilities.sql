-- Intentional SQL injection and destructive-query examples for scanner testing.
SELECT * FROM users WHERE name = '" || :user_input || "';

-- Dangerous operation that should be reviewed carefully.
DROP TABLE audit_log;

-- Weak authorization pattern.
SELECT * FROM accounts WHERE user_id = :user_id OR '1' = '1';
