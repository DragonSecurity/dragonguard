// Package fixtures is never built. It exists so the engines have something
// they must keep finding.
package fixtures

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"

	"golang.org/x/crypto/bcrypt"
)

// dragon-go-sql-string-concat
func query(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	db.Exec("DELETE FROM users WHERE id = " + id)
}

// dragon-go-command-injection
func run(name string) {
	exec.Command("sh", "-c", fmt.Sprintf("rm -rf %s", name))
}

// dragon-go-ignored-error-on-verification
func check(hash, pw []byte) bool {
	_ = bcrypt.CompareHashAndPassword(hash, pw)
	return true
}

// dragon-go-tls-verification-disabled
func client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
