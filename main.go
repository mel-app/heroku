/*
Wrapper for the MEL app backend for running in Heroku.
*/

package main

import (
	"log"
	"os"
	"database/sql"

	_ "github.com/lib/pq"
	"github.com/mel-app/backend/src"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("$PORT must be set")
	}
	dbname := os.Getenv("DATABASE_URL")
	if dbname == "" {
		log.Fatal("$DATABASE_URL must be set")
	}
	db, err := sql.Open("postgres", dbname)
	if err != nil {
		log.Fatal("Error opening database: %q\n", err)
	}
	backend.Run(port, db)
}

// vim: sw=4 ts=4 noexpandtab
