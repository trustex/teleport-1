/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"gopkg.in/ini.v1"
)

func onListDatabases(cf *CLIConf) {
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	var servers []services.Server
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		servers, err = tc.ListDatabaseServers(cf.Context)
		return trace.Wrap(err)
	})
	if err != nil {
		utils.FatalError(err)
	}
	sort.Slice(servers, func(i, j int) bool {
		return servers[i].GetName() < servers[j].GetName()
	})
	// Retrieve profile to be able to show which databases user is logged into.
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	showDatabases(servers, profile.Databases, cf.Verbose)
}

func showDatabases(servers []services.Server, activeDatabases []string, verbose bool) {
	// TODO(r0mant): Add verbose mode, add labels like Apps have.
	t := asciitable.MakeTable([]string{"Name", "Description", "Labels"})
	for _, server := range servers {
		for _, db := range server.GetDatabases() {
			name := db.Name
			if utils.SliceContainsStr(activeDatabases, db.Name) {
				name += "*"
			}
			t.AddRow([]string{name, db.Description, services.LabelsAsString(db.StaticLabels, db.DynamicLabels)})
		}
	}
	fmt.Println(t.AsBuffer().String())
}

func onDatabaseLogin(cf *CLIConf) {
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if profile == nil {
		utils.FatalError(trace.BadParameter("please login using 'tsh login' first"))
	}
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	var servers []services.Server
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		servers, err = tc.ListDatabaseServersFor(cf.Context, cf.DatabaseName)
		return trace.Wrap(err)
	})
	if err != nil {
		utils.FatalError(err)
	}
	if len(servers) == 0 {
		utils.FatalError(trace.NotFound(
			"database %q not found, use 'tsh db ls' to see registered databases", cf.DatabaseName))
	}
	// Obtain certificate with the database name encoded in it.
	log.Debugf("Requesting TLS certificate for database %q on cluster %q.", cf.DatabaseName, profile.Cluster)
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		return tc.ReissueUserCerts(cf.Context, client.ReissueParams{
			RouteToCluster:  profile.Cluster,
			RouteToDatabase: cf.DatabaseName,
		})
	})
	if err != nil {
		utils.FatalError(err)
	}
	// Refresh the profile.
	profile, _, err = client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	// Save connection information to ~/.pg_service.conf file which psql
	// can refer to via "service" connection string parameter.
	pgProfile, err := pgConnectProfileFromProfile(*profile, cf.DatabaseName)
	if err != nil {
		utils.FatalError(err)
	}
	err = pgProfile.Save()
	if err != nil {
		utils.FatalError(err)
	}
	fmt.Printf(`
Connection information for %[1]q has been saved to ~/.pg_service.conf.
You can connect to the database using the following command:

  $ psql "service=%[1]v user=<user> dbname=<dbname>"

Or configure environment variables and use regular CLI flags:

  $ eval $(tsh db env)
  $ psql -U <user> <database>

`, cf.DatabaseName)
}

func onDatabaseLogout(cf *CLIConf) {
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if profile == nil {
		utils.FatalError(trace.BadParameter("not logged in"))
	}
	var found bool
	for _, db := range profile.Databases {
		if db == cf.DatabaseName {
			found = true
			break
		}
	}
	if !found {
		utils.FatalError(trace.BadParameter("not logged in database %q", cf.DatabaseName))
	}
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	err = tc.LogoutDatabase(cf.DatabaseName)
	if err != nil {
		utils.FatalError(err)
	}
	pgProfile, err := pgConnectProfileFromProfile(*profile, cf.DatabaseName)
	if err != nil {
		utils.FatalError(err)
	}
	err = pgProfile.Delete(cf.DatabaseName)
	if err != nil {
		utils.FatalError(err)
	}
	fmt.Printf("logged out of database %q\n", cf.DatabaseName)
}

func onDatabaseEnv(cf *CLIConf) {
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if profile == nil {
		utils.FatalError(trace.BadParameter("please login using 'tsh login' first"))
	}
	if len(profile.Databases) == 0 {
		utils.FatalError(trace.BadParameter("please login using 'tsh db login' first"))
	}
	database := cf.DatabaseName
	if database == "" {
		if len(profile.Databases) > 1 {
			utils.FatalError(trace.BadParameter("multiple databases are available (%v), please select the one to print environment for via --db flag",
				strings.Join(profile.Databases, ", ")))
		}
		database = profile.Databases[0]
	}
	pgProfile, err := pgConnectProfileFromProfile(*profile, database)
	if err != nil {
		utils.FatalError(err)
	}
	for k, v := range pgProfile.AsEnv() {
		fmt.Printf("export %v=%v\n", k, v)
	}
}

type pgConnectProfile struct {
	// Name is the profile name, the database it is for.
	Name string
	// Host is the host to connect to.
	Host string
	// Port is the port number to connect to.
	Port int
	// SSLMode is the SSL connection mode.
	SSLMode string
	// SSLRootCert is the CA certificate path.
	SSLRootCert string
	// SSLCert is the client certificate path.
	SSLCert string
	// SSLKey is the client key path.
	SSLKey string
	// Path is the service file path.
	Path string
}

func pgConnectProfileFromProfile(profile client.ProfileStatus, database string) (*pgConnectProfile, error) {
	addr, err := utils.ParseAddr(profile.ProxyURL.Host)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := user.Current()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &pgConnectProfile{
		Name:        database,
		Host:        addr.Host(),
		Port:        addr.Port(defaults.HTTPListenPort),
		SSLMode:     "verify-ca", // TODO(r0mant): Change to verify-full.
		SSLRootCert: filepath.Join(profile.Dir, "keys", profile.Name, "certs.pem"),
		SSLCert:     filepath.Join(profile.Dir, "keys", profile.Name, fmt.Sprintf("%v-db", profile.Username), profile.Cluster, fmt.Sprintf("%v-x509.pem", database)),
		SSLKey:      filepath.Join(profile.Dir, "keys", profile.Name, profile.Username),
		Path:        filepath.Join(user.HomeDir, ".pg_service.conf"),
	}, nil
}

// AsEnv returns this connection profile as a set of environment variables
// recognized by Postgres clients.
func (p *pgConnectProfile) AsEnv() map[string]string {
	return map[string]string{
		"PGHOST":        p.Host,
		"PGPORT":        strconv.Itoa(p.Port),
		"PGSSLMODE":     p.SSLMode,
		"PGSSLROOTCERT": p.SSLRootCert,
		"PGSSLCERT":     p.SSLCert,
		"PGSSLKEY":      p.SSLKey,
	}
}

// Save saves this connection profile in the ~/.pg_service.conf ini file.
//
// The profile goes into a separate section with the name equal to the
// name of the database that user is logged into and looks like this:
//
//   [postgres]
//   host=localhost
//   port=3080
//   sslmode=verify-full
//   sslrootcert=/home/user/.tsh/keys/127.0.0.1/certs.pem
//   sslcert=/home/user/.tsh/keys/127.0.0.1/user-x509.pem
//   sslkey=/home/user/.tsh/keys/127.0.0.1/user
//
// With the profile like this, a user can refer to it using "service" psql
// parameter:
//
//   $ psql service=postgres <other parameters>
func (p *pgConnectProfile) Save() error {
	// Loose load will ignore file not found error.
	iniFile, err := ini.LooseLoad(p.Path)
	if err != nil {
		return trace.Wrap(err)
	}
	section := iniFile.Section(p.Name)
	if section != nil {
		iniFile.DeleteSection(p.Name)
	}
	section, err = iniFile.NewSection(p.Name)
	if err != nil {
		return trace.Wrap(err)
	}
	section.NewKey("host", p.Host)
	section.NewKey("port", strconv.Itoa(p.Port))
	section.NewKey("sslmode", p.SSLMode)
	section.NewKey("sslrootcert", p.SSLRootCert)
	section.NewKey("sslcert", p.SSLCert)
	section.NewKey("sslkey", p.SSLKey)
	ini.PrettyFormat = false // Pretty format breaks psql.
	return iniFile.SaveTo(p.Path)
}

// Delete deletes the section with the specified name from the service file.
func (p *pgConnectProfile) Delete(name string) error {
	iniFile, err := ini.LooseLoad(p.Path)
	if err != nil {
		return trace.Wrap(err)
	}
	iniFile.DeleteSection(name)
	return iniFile.SaveTo(p.Path)
}
