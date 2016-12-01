/*
Authentication code.

Author:		Alastair Hughes
Contact:	<hobbitalastair at yandex dot com>
*/

package backend

import (
	"bytes"
	"crypto/rand"
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
func authenticateUser(writer http.ResponseWriter, fail func(int), request *http.Request, db *sql.DB) (user string, ok bool) {
	// get the user name and password.
	user, password, ok := request.BasicAuth()
	if !ok {
		writer.Header().Add("WWW-Authenticate", "basic realm=\"\"")
		fail(http.StatusUnauthorized)
		return user, false
	}

	// Retrieve the salt and database password.
	salt := make([]byte, passwordSize)
	dbpassword := []byte("")
	err := db.QueryRow("SELECT salt, password FROM users WHERE name=$1", user).Scan(&salt, &dbpassword)
	if err == sql.ErrNoRows && request.URL.Path == "/login" && request.Method == http.MethodPost {
		// FIXME: Special case creating a new user.
		log.Printf("Creating a new user %s\n", user)
		_, err = rand.Read(salt)
		if err != nil {
			internalError(fail, err)
			return user, false
		}
		key, err := encryptPassword(password, salt)
		if err != nil {
			internalError(fail, err)
			return user, false
		}
		_, err = db.Exec("INSERT INTO users VALUES ($1, $2, $3, $4)", user, salt, key, false)
		if err != nil {
			internalError(fail, err)
			return user, false
		}
		return user, true
	} else if err == sql.ErrNoRows {
		log.Printf("No such user %s\n", user)
		fail(http.StatusForbidden)
		return user, false
	} else if err != nil {
		internalError(fail, err)
		return user, false
	}

	// Check the password.
	if string(dbpassword) == "" {
		// Special case an empty password in the database.
		// This lets us create "public" demonstration accounts.
		return user, true
	}
	key, err := encryptPassword(password, salt)
	if err != nil {
		internalError(fail, err)
		return user, false
	}
	if !bytes.Equal(key, dbpassword) {
		log.Printf("Invalid password for user %s\n", user)
		fail(http.StatusForbidden)
		return user, false
	}
	return user, true
}

// authenticateRequest checks that the given user has permission to complete
// the request.
func authenticateRequest(request *http.Request, defaultResource resource) (ok bool) {
	return ((request.Method == http.MethodGet) && (defaultResource.Permissions()&get != 0)) ||
		((request.Method == http.MethodPut) && (defaultResource.Permissions()&set != 0)) ||
		((request.Method == http.MethodPost) && (defaultResource.Permissions()&create != 0)) ||
		((request.Method == http.MethodDelete) && (defaultResource.Permissions()&delete != 0))
}

// vim: sw=4 ts=4 noexpandtab
