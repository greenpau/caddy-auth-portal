package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/mattn/go-sqlite3"
	"os"
	"sync"
	//"encoding/json"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"
)

// Backend represents authentication provider with SQLite backend.
type Backend struct {
	Realm         string                   `json:"realm,omitempty"`
	Path          string                   `json:"path,omitempty"`
	TokenProvider *jwt.TokenProviderConfig `json:"jwt,omitempty"`
	Authenticator *Authenticator           `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with SQLite backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		TokenProvider: jwt.NewTokenProviderConfig(),
		Authenticator: NewAuthenticator(),
	}
	return b
}

// Authenticator represents database connector.
type Authenticator struct {
	mux       sync.Mutex
	path      string
	salt      int
	userCount int
	db        *sql.DB
	logger    *zap.Logger
}

// NewAuthenticator returns an instance of Authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		salt: 16,
	}
}

// SetPath sets database path.
func (sa *Authenticator) SetPath(s string) {
	sa.path = s
	return
}

// SetSalt sets database path.
func (sa *Authenticator) SetSalt(i int) error {
	if i < 12 {
		return fmt.Errorf("the provided value %d is to small for bcrypt salt", i)
	}
	sa.salt = i
	return nil
}

// CreateUser creates a user in a database
func (sa *Authenticator) CreateUser(userID, userPwd, userRoles, userEmail string) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "INSERT INTO User(first_name, last_name, email, passwordHash) VALUES ($, $, $, $) RETURNING id"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	var userCount int
	err = stmt.QueryRowContext(ctx).Scan(&userCount)
	switch {
	case err == sql.ErrNoRows:
		return fmt.Errorf("sqlite3 query did not return user count")
	case err != nil:
		return fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	default:
		sa.logger.Info("counter number of users in sqlite3", zap.Int("user_count", userCount))
	}

	return nil
}

// Configure check database connectivity and required tables.
func (sa *Authenticator) Configure() error {
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
		defer stmt.Close()
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
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT count(id) FROM User"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	var userCount int
	err = stmt.QueryRowContext(ctx).Scan(&userCount)
	switch {
	case err == sql.ErrNoRows:
		return fmt.Errorf("sqlite3 query did not return user count")
	case err != nil:
		return fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	default:
		sa.logger.Info("counter number of users in sqlite3", zap.Int("user_count", userCount))
	}

	sa.userCount = userCount

	return nil
}

// AuthenticateUser checks the database for the presence of a username
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(username, password string) (*jwt.UserClaims, int, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), sa.salt)
	if err != nil {
		return nil, 500, err
	}
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
	err = stmt.QueryRowContext(ctx, username, passwordHash).Scan(&userID)
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

// ConfigureAuthenticator configures backend for .
func (b *Backend) ConfigureAuthenticator() error {
	if b.Authenticator == nil {
		b.Authenticator = NewAuthenticator()
	}
	b.Authenticator.SetPath(b.Path)
	b.Authenticator.logger = b.logger
	if err := b.Authenticator.Configure(); err != nil {
		return err
	}
	if b.Authenticator.userCount == 0 {
		userID := uuid.New().String()
		userPwd := uuid.New().String()
		if len(userID) < 36 || len(userPwd) < 36 {
			return fmt.Errorf("failed to create default superadmin user")
		}
		userRoles := "internal/superadmin"
		userEmail := userID + "@localdomain.local"
		if err := b.Authenticator.CreateUser(userID, userPwd, userRoles, userEmail); err != nil {
			b.logger.Error("failed to create default superadmin user for the database",
				zap.String("error", err.Error()))
			return err
		}
		b.logger.Info(
			"added superadmin user to the database",
			zap.String("user_id", userID),
			zap.String("user_secret", userPwd),
			zap.String("user_roles", userRoles),
			zap.String("user_email", userEmail),
		)
	}
	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	if b.Path == "" {
		return fmt.Errorf("path is empty")
	}
	return nil
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(reqID string, kv map[string]string) (*jwt.UserClaims, int, error) {
	if kv == nil {
		return nil, 400, fmt.Errorf("No input to authenticate")
	}
	if _, exists := kv["username"]; !exists {
		return nil, 400, fmt.Errorf("No username found")
	}
	if _, exists := kv["password"]; !exists {
		return nil, 401, fmt.Errorf("No password found")
	}
	if b.Authenticator == nil {
		return nil, 500, fmt.Errorf("sqlite3 backend is nil")
	}
	claims, statusCode, err := b.Authenticator.AuthenticateUser(kv["username"], kv["password"])
	if statusCode == 200 {
		claims.Origin = b.TokenProvider.TokenOrigin
		claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
		return claims, statusCode, nil
	}
	return nil, statusCode, err
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
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

	driverVersion, _, _ := sqlite3.Version()
	b.logger.Info(
		"validating SQLite backend",
		zap.String("sqlite_version", driverVersion),
		zap.String("db_path", b.Path),
	)

	if b.Authenticator == nil {
		return fmt.Errorf("sqlite3 authenticator is nil")
	}

	return nil
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Realm
}

// ConfigureTokenProvider configures TokenProvider.
func (b *Backend) ConfigureTokenProvider(upstream *jwt.TokenProviderConfig) error {
	if upstream == nil {
		return fmt.Errorf("upstream token provider is nil")
	}
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

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = logger
	return nil
}
