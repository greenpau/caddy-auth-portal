package forms

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	sqlite "github.com/mattn/go-sqlite3"
	"os"
	"sync"
	//"encoding/json"
	"go.uber.org/zap"
	"time"
)

// SqliteBackend represents authentication provider with SQLite backend.
type SqliteBackend struct {
	Realm         string                   `json:"realm,omitempty"`
	Path          string                   `json:"path,omitempty"`
	TokenProvider *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	Authorizer    *SqliteGuard             `json:"-"`
	logger        *zap.Logger
}

// NewSqliteDatabaseBackend return an instance of authentication provider
// with SQLite backend.
func NewSqliteDatabaseBackend() *SqliteBackend {
	b := &SqliteBackend{
		TokenProvider: jwt.NewTokenProviderConfig(),
		Authorizer:    NewSqliteGuard(),
	}
	return b
}

// SqliteGuard represents database connector.
type SqliteGuard struct {
	mux    sync.Mutex
	path   string
	db     *sql.DB
	logger *zap.Logger
}

// NewSqliteGuard returns an instance of SqliteGuard.
func NewSqliteGuard() *SqliteGuard {
	return &SqliteGuard{}
}

// SetPath sets database path.
func (sa *SqliteGuard) SetPath(s string) {
	sa.path = s
	return
}

// Configure check database connectivity and required tables.
func (sa *SqliteGuard) Configure() error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	sa.logger.Info("sqlite3 backend configuration", zap.String("db_path", sa.path))
	fileInfo, err := os.Stat(sa.path)
	if os.IsNotExist(err) {
		sa.logger.Error("sqlite3 database file does not exists", zap.String("db_path", sa.path))
		return fmt.Errorf("sqlite3 database file does not exists")
	}
	if fileInfo.IsDir() {
		sa.logger.Error("sqlite3 database file path points to a directory", zap.String("db_path", sa.path))
		return fmt.Errorf("sqlite3 database file path points to a directory")
	}
	db, err := sql.Open("sqlite3", sa.path)
	if err != nil {
		return fmt.Errorf("failed to open sqlite3 database at %s: %s", sa.path, err)
	}
	if db == nil {
		return fmt.Errorf("failed to open sqlite3 database at %s: nil", sa.path)
	}
	sa.db = db

	// See https://github.com/membership/membership.db/tree/master/sqlite
	// for schema.
	requiredTables := []string{"User", "UserClaim", "UserRole", "UserLogin", "UserUserRole"}
	for _, t := range requiredTables {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		query := "SELECT name FROM sqlite_master WHERE type='table' AND name = ?"
		stmt, err := sa.db.PrepareContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
		}
		var tableName string
		err = stmt.QueryRowContext(ctx, t).Scan(&tableName)
		switch {
		case err == sql.ErrNoRows:
			return fmt.Errorf("required sqlite3 table not found: %s", t)
		case err != nil:
			return fmt.Errorf("sqlite3 database query failed: %s, error: %s", query, err)
		default:
			sa.logger.Info("required sqlite3 table found", zap.String("table_name", tableName))
		}
		if tableName != t {
			return fmt.Errorf("sqlite3 database response mismatch: %s (expected) vs. %s (received)", t, tableName)
		}
		stmt.Close()
	}

	return nil
}

// AuthenticateUser checks the database for the presence of a username
// and password and returns user claims.
func (sa *SqliteGuard) AuthenticateUser(username, password string) (*jwt.UserClaims, int, error) {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stmt, err := sa.db.PrepareContext(ctx, "SELECT id FROM User WHERE email = ? AND passwordHash = ?")
	if err != nil {
		return nil, 500, err
	}
	defer stmt.Close()

	var userID int
	err = stmt.QueryRowContext(ctx, username, password).Scan(&userID)
	switch {
	case err == sql.ErrNoRows:
		return nil, 401, fmt.Errorf("user identity not found")
	case err != nil:
		return nil, 500, err
	default:
		sa.logger.Info("user identity found", zap.String("username", username), zap.Int("user_id", userID))
	}

	claims := &jwt.UserClaims{}
	claims.Subject = username
	claims.Email = username
	// claims.Name = "Greenberg, Paul"
	claims.Roles = append(claims.Roles, "anonymous")
	claims.Roles = append(claims.Roles, "guest")

	return claims, 200, fmt.Errorf("Authentication is not supported")
}

// Configure configures backend with the authentication provider settings.
func (b *SqliteBackend) Configure(p *AuthProvider) error {
	if p.logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = p.logger

	if b.Authorizer == nil {
		b.Authorizer = NewSqliteGuard()
	}

	b.Authorizer.SetPath(b.Path)
	b.Authorizer.logger = p.logger
	if err := b.Authorizer.Configure(); err != nil {
		return err
	}
	if err := b.ConfigureTokenProvider(p.TokenProvider); err != nil {
		return err
	}

	return nil
}

// ValidateConfig checks whether SqliteBackend has mandatory configuration.
func (b *SqliteBackend) ValidateConfig() error {
	if b.Path == "" {
		return fmt.Errorf("path is empty")
	}
	return nil
}

// Authenticate performs authentication.
func (b *SqliteBackend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, int, error) {
	if kv == nil {
		return nil, 400, fmt.Errorf("No input to authenticate")
	}
	if _, exists := kv["username"]; !exists {
		return nil, 400, fmt.Errorf("No username found")
	}
	if _, exists := kv["password"]; !exists {
		return nil, 401, fmt.Errorf("No password found")
	}
	if b.Authorizer == nil {
		return nil, 500, fmt.Errorf("sqlite3 backend is nil")
	}
	claims, statusCode, err := b.Authorizer.AuthenticateUser(kv["username"], kv["password"])
	if statusCode == 200 {
		claims.Origin = b.TokenProvider.TokenOrigin
		claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
		return claims, statusCode, nil
	}
	return nil, statusCode, err
}

// Validate checks whether SqliteBackend is functional.
func (b *SqliteBackend) Validate(p *AuthProvider) error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return fmt.Errorf("backend logger is nil")
	}

	driverFound := false
	for _, driver := range sql.Drivers() {
		if driver == "sqlite3" {
			driverFound = true
			break
		}
	}
	if !driverFound {
		b.logger.Error("sqlite3 driver not found")
		return fmt.Errorf("sqlite3 driver not found")
	}

	driverVersion, _, _ := sqlite.Version()
	b.logger.Info(
		"validating SQLite backend",
		zap.String("sqlite_version", driverVersion),
		zap.String("db_path", b.Path),
	)

	if b.Authorizer == nil {
		return fmt.Errorf("sqlite3 authorizer is nil")
	}

	return nil
}

// GetRealm return authentication realm.
func (b *SqliteBackend) GetRealm() string {
	return b.Realm
}

// ConfigureTokenProvider configures TokenProvider.
func (b *SqliteBackend) ConfigureTokenProvider(upstream *jwt.TokenProviderConfig) error {
	if b.TokenProvider == nil {
		b.TokenProvider = jwt.NewTokenProviderConfig()
	}
	if b.TokenProvider.TokenName == "" {
		b.TokenProvider.TokenName = upstream.TokenName
	}
	if b.TokenProvider.TokenSecret == "" {
		b.TokenProvider.TokenSecret = upstream.TokenSecret
	}
	if b.TokenProvider.TokenIssuer == "" {
		b.TokenProvider.TokenIssuer = upstream.TokenIssuer
	}
	if b.TokenProvider.TokenOrigin == "" {
		b.TokenProvider.TokenOrigin = upstream.TokenOrigin
	}
	if b.TokenProvider.TokenLifetime == 0 {
		b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	}
	return nil
}
