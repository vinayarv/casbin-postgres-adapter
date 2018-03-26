// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adapter

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/casbin/casbin/model"
	_ "github.com/lib/pq" // This is for MySQL initialization.
	"strconv"
)

// Adapter represents the MySQL adapter for policy storage.
type Adapter struct {
	driverName     string
	dataSourceName string
	db             *sql.DB
	dbSpecified    bool
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(driverName string, dataSourceName string, dbSpecified ...bool) *Adapter {
	a := Adapter{}
	a.driverName = driverName
	a.dataSourceName = dataSourceName

	if len(dbSpecified) == 0 {
		a.dbSpecified = false
	} else if len(dbSpecified) == 1 {
		a.dbSpecified = dbSpecified[0]
	} else {
		panic(errors.New("invalid parameter: dbSpecified"))
	}

	return &a
}

func (a *Adapter) createDatabase() error {
	db, err := sql.Open(a.driverName, a.dataSourceName)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS casbin")
	return err
}

func (a *Adapter) open() {

	if a.dbSpecified {
		db, err := sql.Open(a.driverName, a.dataSourceName)
		if err != nil {
			panic(err)
		}
		a.db = db
	} else {
		if err := a.createDatabase(); err != nil {
			panic(err)
		}

		db, err := sql.Open(a.driverName, a.dataSourceName+"casbin")
		if err != nil {
			panic(err)
		}
		a.db = db
	}

	a.createTable()
}

func (a *Adapter) close() {
	a.db.Close()
}

func (a *Adapter) createTable() {
	_, err := a.db.Exec("CREATE table IF NOT EXISTS policy (ptype VARCHAR(10), v0 VARCHAR(256), v1 VARCHAR(256), v2 VARCHAR(256), v3 VARCHAR(256), v4 VARCHAR(256), v5 VARCHAR(256))")
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) dropTable() {
	_, err := a.db.Exec("DROP table policy")
	if err != nil {
		panic(err)
	}
}

func loadPolicyLine(line string, model model.Model) {
	if line == "" {
		return
	}

	tokens := strings.Split(line, ", ")

	key := tokens[0]
	sec := key[:1]
	model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	a.open()
	defer a.close()

	var (
		ptype string
		v0    sql.NullString
		v1    sql.NullString
		v2    sql.NullString
		v3    sql.NullString
		v4    sql.NullString
		v5    sql.NullString
	)

	rows, err := a.db.Query("select * from policy")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&ptype, &v0, &v1, &v2, &v3, &v4, &v5)
		if err != nil {
			return err
		}

		line := ptype
		if v0.Valid {
			line += ", " + v0.String
		}
		if v1.Valid {
			line += ", " + v1.String
		}
		if v2.Valid {
			line += ", " + v2.String
		}
		if v3.Valid {
			line += ", " + v3.String
		}
		if v4.Valid {
			line += ", " + v4.String
		}
		if v5.Valid {
			line += ", " + v5.String
		}

		loadPolicyLine(line, model)
	}
	err = rows.Err()
	return err
}

func (a *Adapter) writeTableLine(stm *sql.Stmt, ptype string, rule []string) error {
	params := make([]interface{}, 7)
	idx := 0
	params[idx] = ptype
	idx++
	for _, v := range rule {
		params[idx] = v
		idx++
	}
	if _, err := stm.Exec(params...); err != nil {
		return err
	}
	return nil
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.open()
	defer a.close()

	a.dropTable()
	a.createTable()

	stm, err := a.db.Prepare("insert into policy values($1, $2, $3, $4, $5, $6, $7)")
	if err != nil {
		return err
	}
	defer stm.Close()

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			if err = a.writeTableLine(stm, ptype, rule); err != nil {
				return err
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			if err = a.writeTableLine(stm, ptype, rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Adapter) AddPolicy(sec string, ptype string, policy []string) error {
	a.open()
	defer a.close()

	stm, err := a.db.Prepare("insert into policy values($1, $2, $3, $4, $5, $6, $7)")
	if err != nil {
		return err
	}
	defer stm.Close()

	if err = a.writeTableLine(stm, ptype, policy); err != nil{
		return err
	}
	return err
}

func (a *Adapter) RemovePolicy(sec string, ptype string, policy []string) error {

	a.open()
	defer a.close()

	statement := "DELETE FROM policy WHERE ptype = $1"
	for i, _ := range policy {
		statement += " AND v" + strconv.Itoa(i) + " = $"+ strconv.Itoa(i+2)
	}

	stm, err := a.db.Prepare(statement)
	if err != nil {
		return err
	}
	defer stm.Close()

	params := make([]interface{}, len(policy)+1)
	params[0] = ptype
	for i, v := range policy {
		params[i+1] = v
	}

	if _, err := stm.Exec(params...); err != nil {
		return err
	}

	return err
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
