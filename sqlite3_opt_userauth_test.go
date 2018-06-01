// Copyright (C) 2018 G.J.R. Timmer <gjr.timmer@gmail.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

// +build sqlite_userauth

package sqlite3

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func init() {

}

func TestUserAuthentication(t *testing.T) {
	// Create database connection
	var conn *SQLiteConn
	sql.Register("sqlite3_with_conn",
		&SQLiteDriver{
			ConnectHook: func(c *SQLiteConn) error {
				conn = c
				return nil
			},
		})

	connect := func(f string, username, password string) (file string, db *sql.DB, c *SQLiteConn, err error) {
		conn = nil // Clear connection
		file = f   // Copy provided file (f) => file
		if file == "" {
			// Create dummy file
			file = TempFilename(t)
		}

		db, err = sql.Open("sqlite3_with_conn", "file:"+file+fmt.Sprintf("?_auth&_auth_user=%s&_auth_pass=%s", username, password))
		if err != nil {
			defer os.Remove(file)
			return file, nil, nil, err
		}

		// Dummy query to force connection and database creation
		// Will return ErrUnauthorized (SQLITE_AUTH) if user authentication fails
		if _, err = db.Exec("SELECT 1;"); err != nil {
			defer os.Remove(file)
			defer db.Close()
			return file, nil, nil, err
		}
		c = conn

		return
	}

	authEnabled := func(db *sql.DB) (exists bool, err error) {
		err = db.QueryRow("select count(type) from sqlite_master WHERE type='table' and name='sqlite_user';").Scan(&exists)
		return
	}

	addUser := func(db *sql.DB, username, password string, admin int) (rv int, err error) {
		err = db.QueryRow("select auth_user_add(?, ?, ?);", username, password, admin).Scan(&rv)
		return
	}

	userExists := func(db *sql.DB, username string) (rv int, err error) {
		err = db.QueryRow("select count(uname) from sqlite_user where uname=?", username).Scan(&rv)
		return
	}

	Convey("Create Database", t, func() {
		_, db, c, err := connect("", "admin", "admin")
		So(db, ShouldNotBeNil)
		So(c, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db.Close()

		b, err := authEnabled(db)
		So(b, ShouldEqual, true)
		So(err, ShouldBeNil)

		e, err := userExists(db, "admin")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
	})

	Convey("Authorization Success", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)
		db1.Close()

		// Preform authentication
		f2, db2, c2, err := connect(f1, "admin", "admin")
		So(f2, ShouldNotBeBlank)
		So(f1, ShouldEqual, f2)
		So(db2, ShouldNotBeNil)
		So(c2, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db2.Close()
	})

	Convey("Authorization Success (*SQLiteConn)", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db1.Close()

		// Test lower level authentication
		err = c1.Authenticate("admin", "admin")
		So(err, ShouldBeNil)
	})

	Convey("Authorization Failed", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// Perform Invalid Authentication when we connect
		// to a database
		f2, db2, c2, err := connect(f1, "admin", "invalid")
		So(f2, ShouldNotBeBlank)
		So(f1, ShouldEqual, f2)
		So(db2, ShouldBeNil)
		So(c2, ShouldBeNil)
		So(err, ShouldEqual, ErrUnauthorized)
	})

	Convey("Authorization Failed (*SQLiteConn)", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db1.Close()

		// Test lower level authentication
		// We require a successful *SQLiteConn to test this.
		err = c1.Authenticate("admin", "invalid")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, ErrUnauthorized)
	})

	Convey("Add Admin User", t, func() {
		_, db, c, err := connect("", "admin", "admin")
		So(db, ShouldNotBeNil)
		So(c, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db.Close()

		// Add Admin User
		rv, err := addUser(db, "admin2", "admin2", 1)
		So(rv, ShouldEqual, 0) // 0 == C.SQLITE_OK
		So(err, ShouldBeNil)

		e, err := userExists(db, "admin2")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
	})

	Convey("Add Admin User (*SQLiteConn)", t, func() {
		_, db, c, err := connect("", "admin", "admin")
		So(db, ShouldNotBeNil)
		So(c, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db.Close()

		// Test lower level AuthUserAdd
		err = c.AuthUserAdd("admin2", "admin2", true)
		So(err, ShouldBeNil)

		e, err := userExists(db, "admin2")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
	})

	Convey("Add Normal User", t, func() {
		_, db, c, err := connect("", "admin", "admin")
		So(db, ShouldNotBeNil)
		So(c, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db.Close()

		// Add Normal User
		rv, err := addUser(db, "user", "user", 0)
		So(rv, ShouldEqual, 0) // 0 == C.SQLITE_OK
		So(err, ShouldBeNil)

		e, err := userExists(db, "user")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
	})

	Convey("Add Normal User (*SQLiteConn)", t, func() {
		_, db, c, err := connect("", "admin", "admin")
		So(db, ShouldNotBeNil)
		So(c, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db.Close()

		// Test lower level AuthUserAdd
		err = c.AuthUserAdd("user", "user", false)
		So(err, ShouldBeNil)

		e, err := userExists(db, "user")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
	})

	Convey("Add Admin User Insufficient Privileges", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// Add Normal User
		rv, err := addUser(db1, "user", "user", 0)
		So(rv, ShouldEqual, 0) // 0 == C.SQLITE_OK
		So(err, ShouldBeNil)

		e, err := userExists(db1, "user")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
		db1.Close()

		// Reconnect as normal user
		f2, db2, c2, err := connect(f1, "user", "user")
		So(f2, ShouldNotBeBlank)
		So(f1, ShouldEqual, f2)
		So(db2, ShouldNotBeNil)
		So(c2, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db2.Close()

		// Add Admin User
		// Because 'user' is not admin
		// Adding an admin user should now fail
		// because we have insufficient privileges
		rv, err = addUser(db2, "admin2", "admin2", 1)
		So(rv, ShouldEqual, SQLITE_AUTH)
		So(err, ShouldBeNil)
	})

	Convey("Add Admin User Insufficient Privileges (*SQLiteConn)", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// Add Normal User
		rv, err := addUser(db1, "user", "user", 0)
		So(rv, ShouldEqual, 0) // 0 == C.SQLITE_OK
		So(err, ShouldBeNil)

		e, err := userExists(db1, "user")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
		db1.Close()

		// Reconnect as normal user
		f2, db2, c2, err := connect(f1, "user", "user")
		So(f2, ShouldNotBeBlank)
		So(f1, ShouldEqual, f2)
		So(db2, ShouldNotBeNil)
		So(c2, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db2.Close()

		// Add Admin User
		// Because 'user' is not admin
		// Adding an admin user should now fail
		// because we have insufficient privileges
		err = c2.AuthUserAdd("admin2", "admin2", true)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, ErrAdminRequired)
	})

	Convey("Add Normal User Insufficient Privileges", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// Add Normal User
		rv, err := addUser(db1, "user", "user", 0)
		So(rv, ShouldEqual, 0) // 0 == C.SQLITE_OK
		So(err, ShouldBeNil)

		e, err := userExists(db1, "user")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
		db1.Close()

		// Reconnect as normal user
		f2, db2, c2, err := connect(f1, "user", "user")
		So(f2, ShouldNotBeBlank)
		So(f1, ShouldEqual, f2)
		So(db2, ShouldNotBeNil)
		So(c2, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db2.Close()

		// Add Normal User
		// Because 'user' is not admin
		// Adding an normal user should now fail
		// because we have insufficient privileges
		rv, err = addUser(db2, "user2", "user2", 0)
		So(rv, ShouldEqual, SQLITE_AUTH)
		So(err, ShouldBeNil)
	})

	Convey("Add Normal User Insufficient Privileges (*SQLiteConn)", t, func() {
		f1, db1, c1, err := connect("", "admin", "admin")
		So(f1, ShouldNotBeBlank)
		So(db1, ShouldNotBeNil)
		So(c1, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// Add Normal User
		rv, err := addUser(db1, "user", "user", 0)
		So(rv, ShouldEqual, 0) // 0 == C.SQLITE_OK
		So(err, ShouldBeNil)

		e, err := userExists(db1, "user")
		So(err, ShouldBeNil)
		So(e, ShouldEqual, 1)
		db1.Close()

		// Reconnect as normal user
		f2, db2, c2, err := connect(f1, "user", "user")
		So(f2, ShouldNotBeBlank)
		So(f1, ShouldEqual, f2)
		So(db2, ShouldNotBeNil)
		So(c2, ShouldNotBeNil)
		So(err, ShouldBeNil)
		defer db2.Close()

		// Add Normal User
		// Because 'user' is not admin
		// Adding an normal user should now fail
		// because we have insufficient privileges
		// Test lower level AuthUserAdd
		err = c2.AuthUserAdd("user", "user", false)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, ErrAdminRequired)
	})

	Convey("Modify Current Connection Password", t, func() {

	})
}

func TestAuthUserModify(t *testing.T) {
	tempFilename := TempFilename(t)
	defer os.Remove(tempFilename)

	var rv int

	db, err := sql.Open("sqlite3", "file:"+tempFilename+"?_auth&_auth_user=admin&_auth_pass=admin")
	if err != nil {
		t.Fatal("Failed to open database:", err)
	}

	// Dummy Query to force connection
	if _, err := db.Exec("SELECT 1;"); err != nil {
		t.Fatalf("Failed to connect: %s", err)
	}

	if err := db.QueryRow("select auth_user_add('user', 'user', false);").Scan(&rv); err != nil || rv != 0 {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("Failed to create normal user")
	}

	if err := db.QueryRow("select auth_user_change('admin', 'nimda', true);").Scan(&rv); err != nil || rv != 0 {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("Failed to change password")
	}
	db.Close()

	// Re-Connect with new credentials
	db, err = sql.Open("sqlite3", "file:"+tempFilename+"?_auth_user=admin&_auth_pass=nimda")
	if err != nil {
		t.Fatal("Failed to open database:", err)
	}

	if err := db.QueryRow("select count(uname) from sqlite_user where uname = 'admin';").Scan(&rv); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Dummy Query to force connection to test authorization
	if _, err := db.Exec("SELECT 1;"); err != nil && err != ErrUnauthorized {
		t.Fatalf("Failed to connect: %s", err)
	}
}

func TestAuthUserDelete(t *testing.T) {
	tempFilename := TempFilename(t)
	defer os.Remove(tempFilename)

	//var rv int

	db, err := sql.Open("sqlite3", "file:"+tempFilename+"?_auth&_auth_user=admin&_auth_pass=admin")
	if err != nil {
		t.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Dummy Query to force connection to test authorization
	if _, err := db.Exec("SELECT 1;"); err != nil {
		t.Fatalf("Failed to connect: %s", err)
	}

	// Add User
	if _, err := db.Exec("select auth_user_add('user', 'user', false);"); err != nil {
		t.Fatal(err)
	}

	// Verify, their should be now 2 users
	var users int
	if err := db.QueryRow("select count(uname) from sqlite_user;").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 2 {
		t.Fatal("Failed to add user")
	}

	// Delete User
	if _, err := db.Exec("select auth_user_delete('user');"); err != nil {
		t.Fatal(err)
	}

	// Verify their should now only be 1 user remaining, the current logged in admin user
	if err := db.QueryRow("select count(uname) from sqlite_user;").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Fatal("Failed to delete user")
	}
}
