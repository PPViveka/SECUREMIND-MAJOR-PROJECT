package main

import (
    "database/sql"
    "math/rand"
    "os/exec"
)

const apiKey = "demo-api-key-123456789"

func vulnerable(db *sql.DB, userID string) error {
    query := "SELECT * FROM users WHERE id = " + userID
    if _, err := db.Exec(query); err != nil {
        return err
    }
    token := rand.Int()
    command := exec.Command("sh", "-c", userID)
    _ = command.Run()
    _ = token
    return nil
}
