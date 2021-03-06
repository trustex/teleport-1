/*
Copyright 2015-2019 Gravitational, Inc.

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

package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/trace"
)

// WebSession stores key and value used to authenticate with SSH
// notes on behalf of user
type WebSession interface {
	// Resource represents common properties for all resources.
	Resource
	// GetShortName returns visible short name used in logging
	GetShortName() string
	// GetName returns session name
	GetName() string
	// GetUser returns the user this session is associated with
	GetUser() string
	// SetName sets session name
	SetName(string)
	// SetUser sets user associated with this session
	SetUser(string)
	// GetPub is returns public certificate signed by auth server
	GetPub() []byte
	// GetPriv returns private OpenSSH key used to auth with SSH nodes
	GetPriv() []byte
	// SetPriv sets private key
	SetPriv([]byte)
	// GetTLSCert returns PEM encoded TLS certificate associated with session
	GetTLSCert() []byte
	// BearerToken is a special bearer token used for additional
	// bearer authentication
	GetBearerToken() string
	// SetBearerTokenExpiryTime sets bearer token expiry time
	SetBearerTokenExpiryTime(time.Time)
	// SetExpiryTime sets session expiry time
	SetExpiryTime(time.Time)
	// GetBearerTokenExpiryTime - absolute time when token expires
	GetBearerTokenExpiryTime() time.Time
	// GetExpiryTime - absolute time when web session expires
	GetExpiryTime() time.Time
	// V1 returns V1 version of the resource
	V1() *WebSessionV1
	// V2 returns V2 version of the resource
	V2() *WebSessionV2
	// WithoutSecrets returns copy of the web session but without private keys
	WithoutSecrets() WebSession
	// CheckAndSetDefaults checks and set default values for any missing fields.
	CheckAndSetDefaults() error
	// String returns string representation of the session.
	String() string
	// Expiry is the expiration time for this resource.
	Expiry() time.Time
}

// NewWebSession returns new instance of the web session based on the V2 spec
func NewWebSession(name string, kind string, subkind string, spec WebSessionSpecV2) WebSession {
	return &WebSessionV2{
		Kind:    kind,
		SubKind: subkind,
		Version: V2,
		Metadata: Metadata{
			Name:      name,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}
}

func (ws *WebSessionV2) GetKind() string {
	return ws.Kind
}

func (ws *WebSessionV2) GetSubKind() string {
	return ws.SubKind
}

func (ws *WebSessionV2) SetSubKind(subKind string) {
	ws.SubKind = subKind
}

func (ws *WebSessionV2) GetVersion() string {
	return ws.Version
}

func (ws *WebSessionV2) GetName() string {
	return ws.Metadata.Name
}

func (ws *WebSessionV2) SetName(name string) {
	ws.Metadata.Name = name
}

func (ws *WebSessionV2) Expiry() time.Time {
	return ws.Metadata.Expiry()
}

func (ws *WebSessionV2) SetExpiry(expiry time.Time) {
	ws.Metadata.SetExpiry(expiry)
}

func (ws *WebSessionV2) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	ws.Metadata.SetTTL(clock, ttl)
}

func (ws *WebSessionV2) GetMetadata() Metadata {
	return ws.Metadata
}

func (ws *WebSessionV2) GetResourceID() int64 {
	return ws.Metadata.GetID()
}

func (ws *WebSessionV2) SetResourceID(id int64) {
	ws.Metadata.SetID(id)
}

// WithoutSecrets returns copy of the object but without secrets
func (ws *WebSessionV2) WithoutSecrets() WebSession {
	v2 := ws.V2()
	v2.Spec.Priv = nil
	return v2
}

// CheckAndSetDefaults checks and set default values for any missing fields.
func (ws *WebSessionV2) CheckAndSetDefaults() error {
	err := ws.Metadata.CheckAndSetDefaults()
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// String returns string representation of the session.
func (ws *WebSessionV2) String() string {
	return fmt.Sprintf("WebSession(kind=%v,name=%v,id=%v)", ws.GetKind(), ws.GetUser(), ws.GetName())
}

// SetUser sets user associated with this session
func (ws *WebSessionV2) SetUser(u string) {
	ws.Spec.User = u
}

// GetUser returns the user this session is associated with
func (ws *WebSessionV2) GetUser() string {
	return ws.Spec.User
}

// GetShortName returns visible short name used in logging
func (ws *WebSessionV2) GetShortName() string {
	if len(ws.Metadata.Name) < 4 {
		return "<undefined>"
	}
	return ws.Metadata.Name[:4]
}

// GetTLSCert returns PEM encoded TLS certificate associated with session
func (ws *WebSessionV2) GetTLSCert() []byte {
	return ws.Spec.TLSCert
}

// GetPub is returns public certificate signed by auth server
func (ws *WebSessionV2) GetPub() []byte {
	return ws.Spec.Pub
}

// GetPriv returns private OpenSSH key used to auth with SSH nodes
func (ws *WebSessionV2) GetPriv() []byte {
	return ws.Spec.Priv
}

// SetPriv sets private key
func (ws *WebSessionV2) SetPriv(priv []byte) {
	ws.Spec.Priv = priv
}

// BearerToken is a special bearer token used for additional
// bearer authentication
func (ws *WebSessionV2) GetBearerToken() string {
	return ws.Spec.BearerToken
}

// SetBearerTokenExpiryTime sets bearer token expiry time
func (ws *WebSessionV2) SetBearerTokenExpiryTime(tm time.Time) {
	ws.Spec.BearerTokenExpires = tm
}

// SetExpiryTime sets session expiry time
func (ws *WebSessionV2) SetExpiryTime(tm time.Time) {
	ws.Spec.Expires = tm
}

// GetBearerTokenExpiryTime - absolute time when token expires
func (ws *WebSessionV2) GetBearerTokenExpiryTime() time.Time {
	return ws.Spec.BearerTokenExpires
}

// GetExpiryTime - absolute time when web session expires
func (ws *WebSessionV2) GetExpiryTime() time.Time {
	return ws.Spec.Expires
}

// V2 returns V2 version of the resource
func (ws *WebSessionV2) V2() *WebSessionV2 {
	return ws
}

// V1 returns V1 version of the object
func (ws *WebSessionV2) V1() *WebSessionV1 {
	return &WebSessionV1{
		ID:          ws.Metadata.Name,
		Priv:        ws.Spec.Priv,
		Pub:         ws.Spec.Pub,
		BearerToken: ws.Spec.BearerToken,
		Expires:     ws.Spec.Expires,
	}
}

// WebSessionSpecV2Schema is JSON schema for cert authority V2
const WebSessionSpecV2Schema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["pub", "bearer_token", "bearer_token_expires", "expires", "user"],
  "properties": {
    "user": {"type": "string"},
    "pub": {"type": "string"},
    "priv": {"type": "string"},
    "tls_cert": {"type": "string"},
    "bearer_token": {"type": "string"},
    "bearer_token_expires": {"type": "string"},
    "expires": {"type": "string"}%v
  }
}`

// WebSession stores key and value used to authenticate with SSH
// nodes on behalf of user
type WebSessionV1 struct {
	// ID is session ID
	ID string `json:"id"`
	// User is a user this web session is associated with
	User string `json:"user"`
	// Pub is a public certificate signed by auth server
	Pub []byte `json:"pub"`
	// Priv is a private OpenSSH key used to auth with SSH nodes
	Priv []byte `json:"priv,omitempty"`
	// BearerToken is a special bearer token used for additional
	// bearer authentication
	BearerToken string `json:"bearer_token"`
	// Expires - absolute time when token expires
	Expires time.Time `json:"expires"`
}

// V1 returns V1 version of the resource
func (ws *WebSessionV1) V1() *WebSessionV1 {
	return ws
}

// V2 returns V2 version of the resource
func (ws *WebSessionV1) V2() *WebSessionV2 {
	return &WebSessionV2{
		Kind:    KindWebSession,
		Version: V2,
		Metadata: Metadata{
			Name:      ws.ID,
			Namespace: defaults.Namespace,
		},
		Spec: WebSessionSpecV2{
			Pub:                ws.Pub,
			Priv:               ws.Priv,
			BearerToken:        ws.BearerToken,
			Expires:            ws.Expires,
			BearerTokenExpires: ws.Expires,
		},
	}
}

// WithoutSecrets returns copy of the web session but without private keys
func (ws *WebSessionV1) WithoutSecrets() WebSession {
	v2 := ws.V2()
	v2.Spec.Priv = nil
	return nil
}

// SetName sets session name
func (ws *WebSessionV1) SetName(name string) {
	ws.ID = name
}

// SetUser sets user associated with this session
func (ws *WebSessionV1) SetUser(u string) {
	ws.User = u
}

// GetUser returns the user this session is associated with
func (ws *WebSessionV1) GetUser() string {
	return ws.User
}

// GetShortName returns visible short name used in logging
func (ws *WebSessionV1) GetShortName() string {
	if len(ws.ID) < 4 {
		return "<undefined>"
	}
	return ws.ID[:4]
}

// GetName returns session name
func (ws *WebSessionV1) GetName() string {
	return ws.ID
}

// GetPub is returns public certificate signed by auth server
func (ws *WebSessionV1) GetPub() []byte {
	return ws.Pub
}

// GetPriv returns private OpenSSH key used to auth with SSH nodes
func (ws *WebSessionV1) GetPriv() []byte {
	return ws.Priv
}

// BearerToken is a special bearer token used for additional
// bearer authentication
func (ws *WebSessionV1) GetBearerToken() string {
	return ws.BearerToken
}

// Expires - absolute time when token expires
func (ws *WebSessionV1) GetExpiryTime() time.Time {
	return ws.Expires
}

// SetExpiryTime sets session expiry time
func (ws *WebSessionV1) SetExpiryTime(tm time.Time) {
	ws.Expires = tm
}

// GetBearerRoken - absolute time when token expires
func (ws *WebSessionV1) GetBearerTokenExpiryTime() time.Time {
	return ws.Expires
}

// SetBearerTokenExpiryTime sets session expiry time
func (ws *WebSessionV1) SetBearerTokenExpiryTime(tm time.Time) {
	ws.Expires = tm
}

var webSessionMarshaler WebSessionMarshaler = &TeleportWebSessionMarshaler{}

// SetWebSessionMarshaler sets global user marshaler
func SetWebSessionMarshaler(u WebSessionMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	webSessionMarshaler = u
}

// GetWebSessionMarshaler returns currently set user marshaler
func GetWebSessionMarshaler() WebSessionMarshaler {
	marshalerMutex.RLock()
	defer marshalerMutex.RUnlock()
	return webSessionMarshaler
}

// WebSessionMarshaler implements marshal/unmarshal of User implementations
// mostly adds support for extended versions
type WebSessionMarshaler interface {
	// UnmarshalWebSession unmarhsals cert authority from binary representation
	UnmarshalWebSession(bytes []byte, opts ...MarshalOption) (WebSession, error)
	// MarshalWebSession to binary representation
	MarshalWebSession(c WebSession, opts ...MarshalOption) ([]byte, error)
	// GenerateWebSession generates new web session and is used to
	// inject additional data in extenstions
	GenerateWebSession(WebSession) (WebSession, error)
	// ExtendWebSession extends web session and is used to
	// inject additional data in extenstions when session is getting renewed
	ExtendWebSession(WebSession) (WebSession, error)
}

// GetWebSessionSchema returns JSON Schema for web session
func GetWebSessionSchema() string {
	return GetWebSessionSchemaWithExtensions("")
}

// GetWebSessionSchemaWithExtensions returns JSON Schema for web session with user-supplied extensions
func GetWebSessionSchemaWithExtensions(extension string) string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, fmt.Sprintf(WebSessionSpecV2Schema, extension), DefaultDefinitions)
}

type TeleportWebSessionMarshaler struct{}

// GenerateWebSession generates new web session and is used to
// inject additional data in extenstions
func (*TeleportWebSessionMarshaler) GenerateWebSession(ws WebSession) (WebSession, error) {
	return ws, nil
}

// ExtendWebSession renews web session and is used to
// inject additional data in extenstions when session is getting renewed
func (*TeleportWebSessionMarshaler) ExtendWebSession(ws WebSession) (WebSession, error) {
	return ws, nil
}

// UnmarshalWebSession unmarshals web session from on-disk byte format
func (*TeleportWebSessionMarshaler) UnmarshalWebSession(bytes []byte, opts ...MarshalOption) (WebSession, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var h ResourceHeader
	err = json.Unmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case "":
		var ws WebSessionV1
		err := json.Unmarshal(bytes, &ws)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		utils.UTC(&ws.Expires)
		return ws.V2(), nil
	case V2:
		var ws WebSessionV2
		if err := utils.UnmarshalWithSchema(GetWebSessionSchema(), &ws, bytes); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		utils.UTC(&ws.Spec.BearerTokenExpires)
		utils.UTC(&ws.Spec.Expires)

		if err := ws.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			ws.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			ws.SetExpiry(cfg.Expires)
		}

		return &ws, nil
	}

	return nil, trace.BadParameter("web session resource version %v is not supported", h.Version)
}

// MarshalWebSession marshals web session into on-disk representation
func (*TeleportWebSessionMarshaler) MarshalWebSession(ws WebSession, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	type ws1 interface {
		V1() *WebSessionV1
	}
	type ws2 interface {
		V2() *WebSessionV2
	}
	version := cfg.GetVersion()
	switch version {
	case V1:
		v, ok := ws.(ws1)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal session %v", V1)
		}
		return json.Marshal(v.V1())
	case V2:
		v, ok := ws.(ws2)
		if !ok {
			return nil, trace.BadParameter("don't know how to marshal session %v", V2)
		}
		v2 := v.V2()
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *v2
			copy.Metadata.ID = 0
			v2 = &copy
		}
		return utils.FastMarshal(v2)
	default:
		return nil, trace.BadParameter("version %v is not supported", version)
	}
}

// GetAppWebSessionRequest contains the parameters to request an application
// web session.
type GetAppSessionRequest struct {
	// SessionID is the session ID of the application session itself.
	SessionID string
}

// Check validates the request.
func (r *GetAppSessionRequest) Check() error {
	if r.SessionID == "" {
		return trace.BadParameter("session ID missing")
	}
	return nil
}

// CreateAppWebSessionRequest contains the parameters needed to request
// creating an application web session.
type CreateAppSessionRequest struct {
	// Username is the identity of the user requesting the session.
	Username string `json:"username"`
	// ParentSession is the session ID of the parent session.
	ParentSession string `json:"parent_session"`
	// PublicAddr is the public address of the application.
	PublicAddr string `json:"public_addr"`
	// ClusterName is the name of the cluster within which the application is running.
	ClusterName string `json:"cluster_name"`
}

// Check validates the request.
func (r CreateAppSessionRequest) Check() error {
	if r.Username == "" {
		return trace.BadParameter("username missing")
	}
	if r.ParentSession == "" {
		return trace.BadParameter("parent session missing")
	}
	if r.PublicAddr == "" {
		return trace.BadParameter("public address missing")
	}
	if r.ClusterName == "" {
		return trace.BadParameter("cluster name missing")
	}

	return nil
}

// DeleteAppWebSessionRequest are the parameters used to request removal of
// an application web session.
type DeleteAppSessionRequest struct {
	SessionID string `json:"session_id"`
}
