package uaa

import (
	"encoding/gob"
	"net/http"
	"os"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	"golang.org/x/oauth2"
)

const (
	// keys used for session values
	sessionKeyToken    = "token"
	sessionKeyRedirect = "redirect"
	sessionKeyState    = "state"
)

type session struct {
	name  string
	store sessions.Store
}

func init() {
	gob.Register(oauth2.Token{})
}

type Session interface {
	Get(r *http.Request, key string) interface{}
	Set(w http.ResponseWriter, r *http.Request, key string, value interface{}) error
}

func NewSessionStore(name string, hashKey, blockKey []byte) *session {
	if len(hashKey) == 0 {
		hashKey = securecookie.GenerateRandomKey(64)
	}

	blockKey = adjustBlockKey(blockKey)

	store := sessions.NewFilesystemStore(os.TempDir(), hashKey, blockKey)
	store.MaxLength(8096)

	return &session{
		name:  name,
		store: store,
	}
}

// Get returns a session value for a given key. The function returns nil, if the
// key is not present in the session.
func (s *session) Get(r *http.Request, key string) interface{} {
	// store.Get will always return a session, in the error case it will be empty
	sess, _ := s.store.Get(r, s.name)
	return sess.Values[key]
}

// Set stores a value in the session using the provided key.
func (s *session) Set(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
	// store.Get will always return a session, in the error case it will be empty
	sess, _ := s.store.Get(r, s.name)
	sess.Values[key] = value
	return s.store.Save(r, w, sess)
}

// blockKey must either be 32-, 24-, or 16-byte long
func adjustBlockKey(key []byte) []byte {
	if len(key) > 32 {
		key = key[:32]
	}

	if l := len(key); l < 32 && l > 24 {
		key = key[:24]
	}

	if l := len(key); l < 32 && l > 16 {
		key = key[:16]
	}

	if len(key) < 16 {
		key = securecookie.GenerateRandomKey(32)
	}

	return key
}
