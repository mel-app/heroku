/*
Authentication code.

Author:		Alastair Hughes
Contact:	<hobbitalastair at yandex dot com>
*/

package backend

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"database/sql"
	"golang.org/x/crypto/scrypt"
)

const passwordSize = 256

// internalError ends the request and logs an internal error.
func internalError(fail func(int), err error) {
	fail(http.StatusInternalServerError)
	log.Printf("%q\n", err)
}

// SetPassword sets the given user's password.
// TODO: We should not need to export this.
func SetPassword(user, password string, db *sql.DB) error {
	salt := make([]byte, passwordSize)
	err := db.QueryRow("SELECT salt FROM users WHERE name=$1", user).Scan(&salt)
	if err != nil {
		return fmt.Errorf("Failed to find existing salt: %q\n", err)
	}
	key, err := encryptPassword(password, salt)
	if err != nil {
		return fmt.Errorf("Failed to encrypt the user password: %q\n", err)
	}
	_, err = db.Exec("UPDATE users SET password=$1 WHERE name=$2", key, user)
	if err != nil {
		return fmt.Errorf("Failed to update the user password: %q\n", err)
	}
	return nil
}

// encryptPassword salts and encrypts the given password.
func encryptPassword(password string, salt []byte) ([]byte, error) {
	// We salt and encrypt the password to avoid potential security issues if
	// the db is stolen.
	// This appears to be reasonably close to "best practice", but the 1<<16
	// value probably should be checked for sanity.
	// FIXME: We don't store the 1<<16 value in the db, but it should be
	// increased as compute power grows. Doing so is complicated since some way
	// of migrating users from the old value would also need to be implemented.
	return scrypt.Key([]byte(password), salt, 1<<16, 8, 1, passwordSize)
}

// authenticateUser checks that the user and password in the given HTTP request.
func authenticateUser(writer http.ResponseWriter, fail func(int), request *http.Request, db *sql.DB) (user, password string, ok bool) {
	// get the user name and password.
	user, password, ok = request.BasicAuth()
	if !ok {
		writer.Header().Add("WWW-Authenticate", "basic realm=\"\"")
		fail(http.StatusUnauthorized)
		return user, password, false
	}

	// Retrieve the salt and database password.
	salt := make([]byte, passwordSize)
	dbpassword := []byte("")
	err := db.QueryRow("SELECT salt, password FROM users WHERE name=$1", user).Scan(&salt, &dbpassword)
	if err == sql.ErrNoRows && request.URL.Path == "/login" && request.Method == http.MethodPost {
		// FIXME: Special case creating a new user.
		return user, password, true
	} else if err == sql.ErrNoRows {
		log.Printf("No such user %s\n", user)
		fail(http.StatusForbidden)
		return user, password, false
	} else if err != nil {
		internalError(fail, err)
		return user, password, false
	}

	key, err := encryptPassword(password, salt)
	if err != nil {
		internalError(fail, err)
		return user, password, false
	}
	if !bytes.Equal(key, dbpassword) {
		log.Printf("Invalid password for user %s\n", user)
		fail(http.StatusForbidden)
		return user, password, false
	}
	return user, password, true
}

// authenticateRequest checks that the given user has permission to complete
// the request.
func authenticateRequest(request *http.Request, defaultResource resource) (ok bool) {
	return ((request.Method == http.MethodGet) && (defaultResource.forbidden()&get == 0)) ||
		((request.Method == http.MethodPut) && (defaultResource.forbidden()&set == 0)) ||
		((request.Method == http.MethodPost) && (defaultResource.forbidden()&create == 0)) ||
		((request.Method == http.MethodDelete) && (defaultResource.forbidden()&delete == 0))
}

// vim: sw=4 ts=4 noexpandtab
