/*
Database interface code.

Author:		Alastair Hughes
Contact:	<hobbitalastair at yandex dot com>
*/

package backend

import (
	"database/sql"
	"fmt"
	"log"
)

type DB struct {
	db *sql.DB
}

func NewDB(db *sql.DB) DB {
	return DB{db}
}

// SetIsManager updates the manager flag on the given user.
func (d DB) SetIsManager(user string, isManager bool) error {
	_, err := d.db.Exec("UPDATE users SET is_manager=$1 WHERE name=$2",
		isManager, user)
	return err
}

// DeleteUser removes the given user.
func (d DB) DeleteUser(user string) error {
	// Delete all connections to the account.
	for _, table := range []string{"views", "owns"} {
		rows, err := d.db.Query(fmt.Sprintf("SELECT pid FROM %s WHERE name=$1", table), user)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var id uint = 0
			err = rows.Scan(&id)
			if err != nil {
				return err
			}
			project, err := newProject(user, id, d.db)
			if err != nil {
				return err
			}
			err = project.delete()
			if err != nil {
				return err
			}
		}
		if rows.Err() != nil {
			return rows.Err()
		}
	}

	// Actually delete the account.
	_, err := d.db.Exec("DELETE FROM users WHERE name=$1", user)
	return err
}

// Init clears and initialises the database with the expected tables.
// TODO: Figure out how to handle errors (DROP TABLEs can fail, but nothing
//		 else).
func (d DB) Init() {
	exec := []string{
		`DROP TABLE views`,
		`DROP TABLE owns`,
		`DROP TABLE deliverables`,
		`DROP TABLE projects`,
		`DROP TABLE users`,
		`CREATE TABLE users (
			name VARCHAR(320) PRIMARY KEY, -- 320 is the maximum email length.
			salt BYTEA,
			password BYTEA, -- Password is salted and encrypted.
			is_manager BOOL -- True if the user is also a manager.
		)`,
		`CREATE TABLE projects (
			id BIGINT PRIMARY KEY, -- Is this required??
			name VARCHAR(128), -- Type??
			percentage SMALLINT CHECK (percentage >= 0 and percentage <= 100),
			description VARCHAR(512), -- Size??
			updated TIMESTAMP WITH TIME ZONE,
			version INT,
			flag BOOL,
			flag_version INT
		)`,
		`CREATE TABLE deliverables (
			id BIGINT,
			pid BIGINT,
			name VARCHAR(128),
			due TIMESTAMP WITH TIME ZONE,
			percentage SMALLINT CHECK (percentage >= 0 and percentage <= 100),
			submitted BOOL, -- Whether or not the project is submitted.
			description VARCHAR(512), -- Size??
			updated TIMESTAMP WITH TIME ZONE,
			version INT,
			PRIMARY KEY (id, pid)
		)`,
		`CREATE TABLE owns (
			name VARCHAR(320) REFERENCES users,
			pid BIGINT REFERENCES projects,
			PRIMARY KEY (name, pid)
		)`,
		`CREATE TABLE views (
			name VARCHAR(320) REFERENCES users,
			pid BIGINT REFERENCES projects,
			PRIMARY KEY (name, pid)
		)`,
		// Add a couple of test projects.
		`INSERT INTO projects VALUES (0, 'Test Project 0', 30, 'First test project', '1/17/2017', 0, TRUE, 0)`,
		`INSERT INTO projects VALUES (1, 'Test Project 1', 80, 'Second test project', '1/17/2017', 0, FALSE, 0)`,
		`INSERT INTO deliverables VALUES
			(0, 0, 'Deliverable 0', '11/25/2016', 20, FALSE, 'Finish backend', '1/17/2017', 0)`,
		`INSERT INTO deliverables VALUES
			(1, 0, 'Deliverable 1', '12/9/2016', 70, FALSE, 'Finish prototype', '1/17/2017', 0)`,
		// Add some test users.
		`INSERT INTO users VALUES ('beth', '', '', TRUE)`,
		`INSERT INTO users VALUES ('bob', '', '', TRUE)`,
		`INSERT INTO users VALUES ('bill', '', '', TRUE)`,
		`INSERT INTO users VALUES ('ben', '', '', FALSE)`,
		`INSERT INTO owns VALUES ('beth', 0)`,
		`INSERT INTO views VALUES ('ben', 0)`,
		`INSERT INTO owns VALUES ('bob', 1)`,
		`INSERT INTO views VALUES ('ben', 1)`,
		`INSERT INTO views VALUES ('bill', 1)`,
	}

	for _, cmd := range exec {
		_, err := d.db.Exec(cmd)
		if err != nil {
			log.Printf("Error executing '%s': %q\n", cmd, err)
		}
	}

	// Set the default passwords.
	SetPassword("beth", "test", d.db)
	SetPassword("bob", "test", d.db)
	SetPassword("bill", "test", d.db)
	SetPassword("ben", "test", d.db)
}

// vim: sw=4 ts=4 noexpandtab
