package uaa

import (
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	"golang.org/x/oauth2"
)

const defaultSessionName = "uaa_proxy_new"

type session struct {
	name  string
	store sessions.Store
}

func init() {
	gob.Register(oauth2.Token{})
}

func NewSessionStore(hashKey, blockKey []byte) *session {
	if len(hashKey) == 0 {
		hashKey = securecookie.GenerateRandomKey(64)
	}

	blockKey = adjustBlockKey(blockKey)

	store := sessions.NewFilesystemStore(os.TempDir(), hashKey, blockKey)
	store.MaxLength(8096)

	return &session{
		name:  defaultSessionName,
		store: store,
	}
}

func (s *session) Token(r *http.Request) (*oauth2.Token, error) {
	raw, err := s.get(r, "token")
	if err != nil {
		return nil, err
	}

	token, ok := raw.(oauth2.Token)
	if !ok {
		return nil, errors.New("invalid token found in session")
	}

	return &token, nil
}

func (s *session) State(r *http.Request) (string, error) {
	raw, err := s.get(r, "state")
	if err != nil {
		return "", err
	}

	state, ok := raw.(string)
	if !ok {
		return "", errors.New("invalid state found in session")
	}

	return state, nil
}

func (s *session) SetToken(w http.ResponseWriter, r *http.Request, token *oauth2.Token) error {
	return s.set(w, r, "token", *token)
}

func (s *session) SetState(w http.ResponseWriter, r *http.Request, state string) error {
	return s.set(w, r, "state", state)
}

func (s *session) get(r *http.Request, key string) (interface{}, error) {
	// store.Get will always return a session, in the error case it will be empty
	sess, _ := s.store.Get(r, s.name)

	val, found := sess.Values[key]
	if !found {
		return nil, fmt.Errorf("key %q missing from session", key)
	}

	return val, nil
}

func (s *session) set(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
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
