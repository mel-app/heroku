/*
Resource abstractions.

Author:		Alastair Hughes
Contact:	<hobbitalastair at yandex dot com>
*/

package backend

import (
	cryptRand "crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"time"
)

var invalidResource error = fmt.Errorf("Invalid defaultResource\n")
var invalidBody error = fmt.Errorf("Invalid body\n")
var invalidMethod error = fmt.Errorf("Invalid method\n")

// access types (for permission handling).
const (
	get = 1 << iota
	set
	create
	delete
)

const (
	dbNameLen = 128
	dbDescLen = 512
)

// Interface abstracting encoders.
type encoder interface {
	Encode(interface{}) error
}
type decoder interface {
	Decode(interface{}) error
	More() bool
}

// Interface for the various defaultResource types.
type resource interface {
	forbidden() int
	get(encoder) error
	set(decoder) error
	create(decoder, func(string, interface{}) error) error
	delete() error
}

// Fake encoder to allow extracting the current state from a get call.
type mapEncoder struct {
	current map[string]bool
}

func (m *mapEncoder) Encode(item interface{}) error {
	// FIXME: This is pretty ugly and inflexible. Perhaps use reflection
	//  instead?
	m.current[fmt.Sprintf("%v", item)] = true
	return nil
}

// Regular expressions for the various defaultResources.
var (
	loginRe           = regexp.MustCompile(`\A/login\z`)
	projectListRe     = regexp.MustCompile(`\A/projects\z`)
	projectRe         = regexp.MustCompile(`\A/projects/(\d+)\z`)
	flagRe            = regexp.MustCompile(`\A/projects/(\d+)/flag\z`)
	clientListRe      = regexp.MustCompile(`\A/projects/(\d+)/clients\z`)
	clientRe          = regexp.MustCompile(`\A/projects/(\d+)/clients/([^/]+)\z`)
	deliverableListRe = regexp.MustCompile(`\A/projects/(\d+)/deliverables\z`)
	deliverableRe     = regexp.MustCompile(`\A/projects/(\d+)/deliverables/(\d+)\z`)
)

// defaultResource provides a default implementation of all of the methods required
// to implement resource.
type defaultResource struct{}

func (r defaultResource) forbidden() int {
	return get | set | create | delete
}

func (r defaultResource) get(enc encoder) error {
	return invalidMethod
}

func (r defaultResource) set(dec decoder) error {
	return invalidMethod
}

func (r defaultResource) create(dec decoder, success func(string, interface{}) error) error {
	return invalidMethod
}

func (r defaultResource) delete() error {
	return invalidMethod
}

type loginResource struct {
	resource
	user       string
	password   string
	exists     bool
	is_manager bool
	db         *sql.DB
}

type login struct {
	Username string
	Password string // Note that this field is largely unused.
	Manager  bool
}

// FIXME: Both in login creation and password change, check for a weak
//		  password.

func (l *loginResource) forbidden() int {
	// Anyone can access the login resource, bar create if the account already
	// exists.
	if l.exists {
		return create
	}
	return 0
}

// get for loginResource returns some basic information about the user.
// It can also be used to check login credentials.
func (l *loginResource) get(enc encoder) error {
	return enc.Encode(login{Username: l.user, Manager: l.is_manager})
}

// set for loginResource changes the password.
func (l *loginResource) set(dec decoder) error {
	login := login{}
	err := dec.Decode(&login)
	if err != nil {
		return invalidBody
	}
	return SetPassword(l.user, login.Password, l.db)
}

// create for loginResource creates a new account.
func (l *loginResource) create(dec decoder, success func(string, interface{}) error) error {
	salt := make([]byte, passwordSize)
	_, err := cryptRand.Read(salt)
	if err != nil {
		return err
	}
	key, err := encryptPassword(l.password, salt)
	if err != nil {
		return err
	}
	_, err = l.db.Exec("INSERT INTO users VALUES ($1, $2, $3, $4)",
		l.user, salt, key, false)
	if err != nil {
		return err
	}
	return success("/login", login{Username: l.user, Manager: false})
}

// delete for loginResource deletes that account, and any connections to
// projects.
func (l *loginResource) delete() error {
	return NewDB(l.db).DeleteUser(l.user)
}

// newLogin creates a new loginResouces.
// It saves the is_manager and exists state when creating the resource, since
// they are used later in get() and forbidden().
func newLogin(user string, password string, db *sql.DB) (resource, error) {
	l := loginResource{defaultResource{}, user, password, true, false, db}
	err := db.QueryRow("SELECT is_manager FROM users WHERE name=$1", user).Scan(&l.is_manager)
	if err == sql.ErrNoRows {
		l.exists = false
		err = nil
	}
	return &l, err
}

type projectList struct {
	resource
	user       string
	is_manager bool
	db         *sql.DB
}

func (l *projectList) forbidden() int {
	if l.is_manager {
		return 0
	}
	return create
}

func (l *projectList) get(enc encoder) error {
	for _, table := range []string{"views", "owns"} {
		rows, err := l.db.Query(fmt.Sprintf("SELECT pid FROM %s WHERE name=$1", table), l.user)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			id := -1
			err = rows.Scan(&id)
			if err != nil {
				return err
			}
			err = enc.Encode(id)
			if err != nil {
				return err
			}
		}
		if rows.Err() != nil {
			return rows.Err()
		}
	}
	return nil
}

// create a new project.
func (l *projectList) create(dec decoder, success func(string, interface{}) error) error {
	project := project{}
	err := dec.Decode(&project)
	if err != nil || !project.valid() {
		return invalidBody
	}
	project.Id = uint(rand.Int())
	_, err = l.db.Exec("INSERT INTO projects VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		project.Id, project.Name, project.Percentage, project.Description,
		project.Updated, 0, false, 0)
	if err != nil {
		return err
	}

	// Add the user to the project.
	_, err = l.db.Exec("INSERT INTO owns VALUES ($1, $2)", l.user, project.Id)
	if err != nil {
		return err
	}
	return success(fmt.Sprintf("/projects/%d", project.Id), project)
}

func newProjectList(user string, db *sql.DB) (resource, error) {
	p := projectList{defaultResource{}, user, false, db}
	// Check if the user is a manager.
	err := db.QueryRow("SELECT is_manager FROM users WHERE name=$1", user).Scan(&p.is_manager)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type projectResource struct {
	resource
	pid   uint
	db    *sql.DB
	user  string
	owns  bool
	views bool
}

type project struct {
	Id          uint
	Name        string
	Percentage  uint
	Description string
	Updated     string
	Version     uint
	Owns        bool
}

// valid returns true if the given project looks like it should fit in the
// database with no errors.
// FIXME: Validate any dates.
func (p project) valid() bool {
	return (p.Percentage <= 100) &&
		(len(p.Name) < dbNameLen) && (len(p.Name) > 0) &&
		(len(p.Description) < dbDescLen) &&
		(len(p.Updated) != 0)
}

func (p *projectResource) forbidden() int {
	if p.owns {
		return 0
	} else if p.views {
		return set
	}
	return get | set | delete
}

func (p *projectResource) get(enc encoder) error {
	name, percentage, description, updated, version := "", 0, "", "", 0
	err := p.db.QueryRow("SELECT name, percentage, description, updated, version FROM projects WHERE id=$1", p.pid).
		Scan(&name, &percentage, &description, &updated, &version)
	if err != nil {
		return err
	}
	project := project{p.pid, name, uint(percentage), description, updated, uint(version), p.owns}
	return enc.Encode(project)
}

// set the project state on the server.
// We override any existing state as I have not implemented any kind
// of synchronisation.
// FIXME: Add synchronisation.
func (p *projectResource) set(dec decoder) error {
	project := project{}
	err := dec.Decode(&project)
	if err != nil || !project.valid() || project.Id != p.pid {
		return invalidBody
	}
	_, err = p.db.Exec("UPDATE projects SET name=$1, percentage=$2, description=$3, updated=$4 WHERE id=$5",
		project.Name, project.Percentage, project.Description, project.Updated, p.pid)
	return err
}

// delete the given project from the current user.
// This should remove the current user from the project.
// If there are no managers left for the given project, delete it, any
// deliverables, and any viewing relations involving it.
func (p *projectResource) delete() error {
	var err error = nil
	if !p.owns {
		// Not an owner.
		_, err = p.db.Exec("DELETE FROM views WHERE name=$1 and pid=$2",
			p.user, p.pid)
	} else {
		// Project owner.
		_, err = p.db.Exec("DELETE FROM owns WHERE name=$1 and pid=$2",
			p.user, p.pid)
		if err != nil {
			return err
		}
		// Check for other managers.
		dbpid := 0
		err = p.db.QueryRow("SELECT pid FROM owns WHERE name=$1 and pid=$2",
			p.user, p.pid).Scan(&dbpid)
		if err == sql.ErrNoRows {
			// Remove any viewers.
			_, err = p.db.Exec("DELETE FROM views WHERE pid=$1", p.pid)
			if err != nil {
				return err
			}
			// Remove any deliverables.
			_, err = p.db.Exec("DELETE FROM deliverables WHERE pid=$1", p.pid)
			if err != nil {
				return err
			}
			// Remove the project.
			_, err = p.db.Exec("DELETE FROM projects WHERE id=$1", p.pid)
		}
	}
	return err
}

func newProject(user string, pid uint, db *sql.DB) (*projectResource, error) {
	p := projectResource{defaultResource{}, pid, db, user, false, false}

	// Find the user.
	dbpid := 0
	for _, table := range []string{"views", "owns"} {
		err := db.QueryRow(fmt.Sprintf("SELECT pid FROM %s WHERE name=$1 and pid=$2", table), user, pid).Scan(&dbpid)
		if err == nil {
			if table == "owns" {
				p.owns = true
			} else {
				p.views = true
			}
		} else if err != sql.ErrNoRows {
			return nil, err
		}
	}

	return &p, nil
}

type flagResource struct {
	resource
	pid     uint
	project *projectResource
	db      *sql.DB
}

type flag struct {
	Version uint
	Value   bool
}

func (f *flagResource) forbidden() int {
	// Everyone in the project can read and write to the flag.
	if f.project.owns || f.project.views {
		return 0
	}
	return get | set
}

func (f *flagResource) get(enc encoder) error {
	flag := flag{0, false}
	err := f.db.QueryRow("SELECT flag, flag_version FROM projects WHERE id=$1", f.pid).Scan(&(flag.Value), &(flag.Version))
	if err != nil {
		return err
	}
	return enc.Encode(flag)
}

func (f *flagResource) set(dec decoder) error {
	// Decode the uploaded flag.
	update := flag{0, false}
	err := dec.Decode(&update)
	if err != nil {
		return invalidBody
	}

	// get the saved flag.
	cur := flag{0, false}
	err = f.db.QueryRow("SELECT flag, flag_version FROM projects WHERE id=$1", f.pid).Scan(&(cur.Value), &(cur.Version))
	if err != nil {
		return err
	}

	// Reject invalid versions.
	if update.Version > cur.Version {
		return invalidBody
	}

	// Compare and sync.
	// If the version from the client is equal to the version on the server,
	// use the value from the client and increment the server version.
	// Otherwise, just use the server version.
	if update.Version == cur.Version && update.Value != cur.Value {
		_, err = f.db.Exec("UPDATE projects SET flag=$1, flag_version=$2 WHERE id=$3",
			update.Value, update.Version+1, f.pid)
		return err
	}
	return nil
}

func newFlag(user string, pid uint, db *sql.DB) (resource, error) {
	proj, err := newProject(user, pid, db)
	return &flagResource{defaultResource{}, pid, proj, db}, err
}

type clientList struct {
	resource
	pid     uint
	project *projectResource
	db      *sql.DB
}

func (c *clientList) forbidden() int {
	if c.project.owns {
		return 0
	}
	return get | create
}

func (c *clientList) get(enc encoder) error {
	rows, err := c.db.Query("SELECT name FROM views WHERE pid=$1", c.pid)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		name := ""
		err = rows.Scan(&name)
		if err != nil {
			return err
		}
		err = enc.Encode(base32.StdEncoding.EncodeToString([]byte(name)))
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *clientList) create(dec decoder, success func(string, interface{}) error) error {
	client := client{}
	err := dec.Decode(&client)
	if err != nil {
		return invalidBody
	}

	// Check if the user exists. This is strictly not required, but lets us
	// warn the user if the user made a typo.
	dbuser := ""
	err = c.db.QueryRow("SELECT name FROM users WHERE name=$1", client.Name).
		Scan(&dbuser)
	if err == sql.ErrNoRows {
		return invalidBody
	} else if err != nil {
		return err
	}

	_, err = c.db.Exec("INSERT INTO views VALUES ($1, $2)", client.Name, c.pid)
	if err != nil {
		return err
	}

	// Populate the Id field; this will be accessed through a base32 encoding
	// of the Name field.
	client.Id = base32.StdEncoding.EncodeToString([]byte(client.Name))

	return success(fmt.Sprintf("/projects/%d/clients/%s", c.pid, client.Id), client)
}

func newClientList(user string, pid uint, db *sql.DB) (resource, error) {
	proj, err := newProject(user, pid, db)
	return &clientList{defaultResource{}, pid, proj, db}, err
}

type clientResource struct {
	resource
	id      string
	name    string
	pid     uint
	project *projectResource
	db      *sql.DB
}

type client struct {
	Id        string // base32 encoded Name
	Name      string
	IsManager bool // TODO: Support adding/removing managers through this.
}

func (c *clientResource) forbidden() int {
	if c.project.owns {
		return 0
	}
	return get | delete
}

func (c *clientResource) get(enc encoder) error {
	client := client{}
	client.Id = c.id
	client.Name = c.name
	client.IsManager = false // We don't support sending this information.
	return enc.Encode(client)
}

func (c *clientResource) delete() error {
	_, err := c.db.Exec("DELETE FROM views WHERE name=$1 and pid=$2", c.name, c.pid)
	return err
}

func newClient(user, id, name string, pid uint, db *sql.DB) (resource, error) {
	proj, err := newProject(user, pid, db)
	return &clientResource{defaultResource{}, id, name, pid, proj, db}, err
}

type deliverableList struct {
	resource
	pid     uint
	project *projectResource
	db      *sql.DB
}

func (l *deliverableList) forbidden() int {
	if l.project.owns {
		return 0
	} else if l.project.views {
		return create
	}
	return get | create
}

func (l *deliverableList) get(enc encoder) error {
	rows, err := l.db.Query("SELECT id FROM deliverables WHERE pid=$1", l.pid)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		id := -1
		err = rows.Scan(&id)
		if err != nil {
			return err
		}
		err = enc.Encode(id)
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

// create for deliverableList creates a new deliverable.
func (l *deliverableList) create(dec decoder, success func(string, interface{}) error) error {
	v := deliverable{}
	err := dec.Decode(&v)
	if err != nil || !v.valid() {
		return invalidBody
	}
	v.Id = uint(rand.Int())
	_, err = l.db.Exec("INSERT INTO deliverables VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		v.Id, l.pid, v.Name, v.Due, v.Percentage, v.Submitted, v.Description, v.Updated, 0)
	if err != nil {
		return err
	}
	return success(fmt.Sprintf("/projects/%d/deliverables/%d", l.pid, v.Id), v)
}

func newDeliverableList(user string, pid uint, db *sql.DB) (resource, error) {
	proj, err := newProject(user, pid, db)
	return &deliverableList{defaultResource{}, pid, proj, db}, err
}

type deliverableResource struct {
	resource
	id      uint
	pid     uint
	project *projectResource
	db      *sql.DB
}

type deliverable struct {
	Id          uint
	Name        string
	Due         string
	Percentage  uint
	Submitted   bool
	Description string
	Updated     string
	Version     uint
}

// valid of deliverables returns true if the value will fit in the database and
// is valid.
// FIXME: Validate any dates.
func (d deliverable) valid() bool {
	return (d.Percentage <= 100) &&
		(len(d.Name) < dbNameLen) && (len(d.Name) > 0) &&
		(len(d.Description) < dbDescLen) && (len(d.Description) > 0) &&
		(len(d.Updated) != 0) && (len(d.Due) != 0)
}

func (d *deliverableResource) forbidden() int {
	if d.project.owns {
		return 0
	} else if d.project.views {
		return set | delete
	}
	return get | set | delete
}

func (d *deliverableResource) get(enc encoder) error {
	v := deliverable{}
	err := d.db.QueryRow("SELECT name, due, percentage, submitted, description, updated, version FROM deliverables WHERE id=$1 and pid=$2", d.id, d.pid).
		Scan(&v.Name, &v.Due, &v.Percentage, &v.Submitted, &v.Description, &v.Updated, &v.Version)
	if err != nil {
		return err
	}
	return enc.Encode(v)
}

func (d *deliverableResource) set(dec decoder) error {
	v := deliverable{}
	err := dec.Decode(&v)
	if err != nil || !v.valid() {
		return invalidBody
	}
	_, err = d.db.Exec("UPDATE deliverables SET name=$1, due=$2, percentage=$3, submitted=$4, description=$5, updated=$6 WHERE id=$7 and pid=$8",
		v.Name, v.Due, v.Percentage, v.Submitted, v.Description, v.Updated, d.id, d.pid)
	return err
}

func (d *deliverableResource) delete() error {
	_, err := d.db.Exec("DELETE FROM deliverables WHERE id=$1 and pid=$2",
		d.id, d.pid)
	return err
}

func newDeliverable(user string, id uint, pid uint, db *sql.DB) (resource, error) {
	proj, err := newProject(user, pid, db)
	if err != nil {
		return nil, err
	}

	// Check that the deliverable actually exists.
	dbpid := 0
	err = db.QueryRow("SELECT pid FROM deliverables WHERE id=$1 and pid=$2", id, pid).Scan(&dbpid)
	if err == sql.ErrNoRows {
		return nil, invalidResource
	} else if err != nil {
		return nil, err
	}
	return &deliverableResource{defaultResource{}, id, pid, proj, db}, nil
}

// fromURI returns the defaultResource corresponding to the given URI.
func fromURI(user, password, uri string, db *sql.DB) (resource, error) {
	// Match the path to the regular expressions.
	if loginRe.MatchString(uri) {
		return newLogin(user, password, db)
	} else if projectListRe.MatchString(uri) {
		return newProjectList(user, db)
	} else if projectRe.MatchString(uri) {
		pid, err := strconv.Atoi(projectRe.FindStringSubmatch(uri)[1])
		if err != nil {
			return nil, invalidResource
		}
		return newProject(user, uint(pid), db)
	} else if flagRe.MatchString(uri) {
		pid, err := strconv.Atoi(flagRe.FindStringSubmatch(uri)[1])
		if err != nil {
			return nil, invalidResource
		}
		return newFlag(user, uint(pid), db)
	} else if clientListRe.MatchString(uri) {
		pid, err := strconv.Atoi(clientListRe.FindStringSubmatch(uri)[1])
		if err != nil {
			return nil, invalidResource
		}
		return newClientList(user, uint(pid), db)
	} else if clientRe.MatchString(uri) {
		pid, err := strconv.Atoi(clientRe.FindStringSubmatch(uri)[1])
		if err != nil {
			return nil, invalidResource
		}
		id := clientRe.FindStringSubmatch(uri)[2]
		name, err := base32.StdEncoding.DecodeString(id)
		if err != nil {
			return nil, invalidResource
		}
		return newClient(user, id, string(name), uint(pid), db)
	} else if deliverableListRe.MatchString(uri) {
		pid, err := strconv.Atoi(deliverableListRe.FindStringSubmatch(uri)[1])
		if err != nil {
			return nil, invalidResource
		}
		return newDeliverableList(user, uint(pid), db)
	} else if deliverableRe.MatchString(uri) {
		pid, err := strconv.Atoi(deliverableRe.FindStringSubmatch(uri)[1])
		if err != nil {
			return nil, invalidResource
		}
		id, err := strconv.Atoi(deliverableRe.FindStringSubmatch(uri)[2])
		if err != nil {
			return nil, invalidResource
		}
		return newDeliverable(user, uint(id), uint(pid), db)
	} else {
		return nil, invalidResource
	}
}

// seed the PRNG.
// This *must* be called before using fromURI.
func seed() {
	rand.Seed(time.Now().Unix())
}

// vim: sw=4 ts=4 noexpandtab
