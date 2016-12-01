/*
MEL app backend.



Author:		Alastair Hughes
Contact:	<hobbitalastair at yandex dot com>
*/

package backend

import (
	"encoding/json"
	"log"
	"net/http"

	"database/sql"
)

// handle a single HTTP request.
func handle(writer http.ResponseWriter, request *http.Request, dbtype, dbname string) {
	// Wrapper for failing functions.
	fail := func(status int) { http.Error(writer, http.StatusText(status), status) }

	// Open the database.
	db, err := sql.Open(dbtype, dbname)
	if err != nil {
		internalError(fail, err)
		return
	}

	// Authenticate the user.
	user, ok := authenticateUser(writer, fail, request, db)
	if !ok {
		return
	}

	// get the corresponding defaultResource and authenticate the request.
	defaultResource, err := fromURI(user, request.URL.Path, db)
	if err == invalidResource {
		http.NotFound(writer, request)
		return
	} else if err != nil {
		internalError(fail, err)
		return
	}
	if !authenticateRequest(request, defaultResource) {
		fail(http.StatusForbidden)
		return
	}

	// Respond.
	enc := json.NewEncoder(writer)
	enc.SetEscapeHTML(true)
	switch request.Method {
	case http.MethodGet:
		err = defaultResource.get(enc)
	case http.MethodPut:
		err = defaultResource.set(json.NewDecoder(request.Body))
	case http.MethodPost:
		// Posts need to return 201 with a Location header with the URI to the
		// newly created defaultResource.
		// They should also use enc to write a representation of the object
		// created, preferably including the id.
		err = defaultResource.create(json.NewDecoder(request.Body),
			func(location string, item interface{}) error {
				writer.Header().Add("Location", location)
				writer.WriteHeader(http.StatusCreated)
				return enc.Encode(item)
			})
	case http.MethodDelete:
		err = defaultResource.delete()
	default:
		err = invalidMethod
	}
	if err == invalidBody {
		fail(http.StatusBadRequest)
	} else if err == invalidMethod {
		fail(http.StatusMethodNotAllowed)
	} else if err != nil {
		internalError(fail, err)
	}
}

// Run the server on the given port, connecting to the given database.
// dbtype and dbname are passed to the sql module's open function.
func Run(port, dbtype, dbname string) {
	log.Printf("Running on port :%s, with dbtype %s and dbname %s\n", port,
		dbtype, dbname)
	seed()
	log.Fatal(http.ListenAndServe(":"+port,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handle(w, r, dbtype, dbname)
		}),
	))
}

// vim: sw=4 ts=4 noexpandtab
