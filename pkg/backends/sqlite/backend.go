package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
	"sync"
	"time"
)

var globalAuthenticator *Authenticator

func init() {
	globalAuthenticator = NewAuthenticator()
	return
}

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
		Authenticator: globalAuthenticator,
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

// UserCount returns database user count.
func (sa *Authenticator) UserCount() (int, error) {
	var userCount int
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT count(id) FROM Users"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return userCount, fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	err = stmt.QueryRowContext(ctx).Scan(&userCount)
	switch {
	case err == sql.ErrNoRows:
		return userCount, fmt.Errorf("sqlite3 query did not return user count")
	case err != nil:
		return userCount, fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	default:
		sa.logger.Info("counted number of users in sqlite3", zap.Int("user_count", userCount))
	}
	return userCount, nil

}

// CreateUser creates a user in a database
func (sa *Authenticator) CreateUser(userName, userPwd, userEmail string, userClaims map[string]interface{}) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(userPwd), sa.salt)
	if err != nil {
		return fmt.Errorf("failed generating password hash for user identity with email %s", userEmail)
	}
	sa.mux.Lock()
	defer sa.mux.Unlock()

	// Check whether the email is already registered with an account.
	userCount, err := sa.GetUserEmailCount(userEmail)
	if err != nil {
		return err
	}
	if userCount > 0 {
		return fmt.Errorf("user identity with email %s already exists", userEmail)
	}

	// Create user indentity in Users table
	if err := sa.CreateUserID(userName, userEmail, passwordHash); err != nil {
		return err
	}

	// Search for the created user identity in User
	userCount, err = sa.GetUserEmailCount(userEmail)
	if err != nil {
		return err
	}
	if userCount == 0 {
		return fmt.Errorf("failed creating user identity for email %s", userEmail)
	}

	// Get user id for the created user identity in User
	userID, userPasswordHash, _, err := sa.GetUserID(userEmail)
	if err != nil {
		return err
	}
	if userID == 0 {
		return fmt.Errorf("failed creating user identity for email %s, user id 0", userEmail)
	}

	// Compare password hashes
	if err := bcrypt.CompareHashAndPassword([]byte(userPasswordHash), []byte(userPwd)); err != nil {
		return fmt.Errorf("failed creating user identity for email %s, password hash mismatch", userEmail)
	}

	// Add roles to the user identity
	if userClaims != nil {
		for k, v := range userClaims {
			switch k {
			case "roles", "org":
				if err := sa.AddUserClaim(userID, k, v.(string)); err != nil {
					sa.logger.Warn(
						"failed adding user claim",
						zap.String("claim_type", k),
						zap.Int("user_id", userID),
						zap.String("user_email", userEmail),
					)
					continue
				}
				sa.logger.Info(
					"added user claim",
					zap.String("claim_type", k),
					zap.String("claim_value", v.(string)),
					zap.Int("user_id", userID),
					zap.String("user_email", userEmail),
				)
			default:
				sa.logger.Warn("user claim not supported", zap.String("claim", k))
			}
		}
	}

	sa.logger.Info(
		"created new user",
		zap.Int("user_id", userID),
		zap.String("user_name", userName),
		zap.String("user_email", userEmail),
		zap.Any("user_claims", userClaims),
	)
	return nil
}

// AddUserClaim adds user claim.
func (sa *Authenticator) AddUserClaim(userID int, claimType string, claimValue string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "INSERT INTO UserClaims(userId,claimType,claimValue) VALUES (?, ?, ?)"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	insertResult, err := stmt.ExecContext(ctx, userID, claimType, claimValue)
	if err != nil {
		return fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	}
	rows, err := insertResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite3 user count query failed: %s, error on RowsAffected: %s", query, err)
	}
	if rows != 1 {
		return fmt.Errorf("sqlite3 user count query failed: %s, error on RowsAffected, unexpected number of rows: %d", query, rows)
	}
	return nil
}

// GetUserID returns user id from the combination of email/username and password hash.
func (sa *Authenticator) GetUserID(userInput string) (int, string, string, error) {
	var userID int
	var userEmail string
	var userPasswordHash string
	column := "userName"
	if strings.Contains(userInput, "@") {
		column = "email"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT id, email, passwordHash FROM Users WHERE " + column + " = ?"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return userID, userPasswordHash, userEmail, fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	err = stmt.QueryRowContext(ctx, userInput).Scan(&userID, &userEmail, &userPasswordHash)
	switch {
	case err == sql.ErrNoRows:
		return userID, userPasswordHash, userEmail, fmt.Errorf("user identity not found")
	case err != nil:
		return userID, userPasswordHash, userEmail, fmt.Errorf("sqlite3 database query failed: %s, error: %s", query, err)
	default:
		sa.logger.Info("found user identity", zap.String("user_input", userInput), zap.Int("user_id", userID))
	}
	return userID, userPasswordHash, userEmail, nil
}

// GetUserEmailCount returns the number of entries with this email address
func (sa *Authenticator) GetUserEmailCount(userEmail string) (int, error) {
	var userCount int
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT count(email) FROM Users WHERE email = ?"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return userCount, fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	err = stmt.QueryRowContext(ctx, userEmail).Scan(&userCount)
	switch {
	case err == sql.ErrNoRows:
		return userCount, fmt.Errorf("sqlite3 query did not return user count")
	case err != nil:
		return userCount, fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	default:
		sa.logger.Info("counted number of users in sqlite3", zap.Int("user_count", userCount))
	}
	return userCount, nil
}

// GetUserNameCount returns the number of entries with this username
func (sa *Authenticator) GetUserNameCount(userName string) (int, error) {
	var userCount int
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT count(userName) FROM Users WHERE userName = ?"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return userCount, fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	err = stmt.QueryRowContext(ctx, userName).Scan(&userCount)
	switch {
	case err == sql.ErrNoRows:
		return userCount, fmt.Errorf("sqlite3 query did not return user count")
	case err != nil:
		return userCount, fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	default:
		sa.logger.Info("counted number of users in sqlite3", zap.Int("user_count", userCount))
	}
	return userCount, nil
}

// CreateUserID create user identity in Users table.
func (sa *Authenticator) CreateUserID(userName, userEmail string, passwordHash []byte) error {
	initialUserCount, err := sa.UserCount()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "INSERT INTO Users(userName,email,passwordHash) VALUES (?, ?, ?)"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	insertResult, err := stmt.ExecContext(ctx, userName, userEmail, passwordHash)
	if err != nil {
		return fmt.Errorf("sqlite3 user count query failed: %s, error: %s", query, err)
	}
	rows, err := insertResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite3 user count query failed: %s, error on RowsAffected: %s", query, err)
	}
	if rows != 1 {
		return fmt.Errorf("sqlite3 user count query failed: %s, error on RowsAffected, unexpected number of rows: %d", query, rows)
	}

	sa.logger.Info(
		"created entry in Users table",
		zap.String("user_email", userEmail),
	)

	finalUserCount, err := sa.UserCount()
	if err != nil {
		return err
	}

	if finalUserCount-initialUserCount != 1 {
		return fmt.Errorf("sqlite3 user count mismatch: %d (initial) vs. %d (final)", initialUserCount, finalUserCount)
	}

	return nil
}

// GetUserAttributes returns user attributes.
func (sa *Authenticator) GetUserAttributes(userID int) (map[string]string, error) {
	userAttributes := make(map[string]string)
	columns := []string{
		"firstName", "lastName", "caption", "userName", "phoneNumber",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT " + strings.Join(columns, ", ") + " FROM Users WHERE id = ?"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	var firstName, lastName, caption, userName, phoneNumber interface{}
	err = stmt.QueryRowContext(ctx, userID).Scan(&firstName, &lastName, &caption, &userName, &phoneNumber)
	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("user identity not found")
	case err != nil:
		return nil, fmt.Errorf("sqlite3 database query failed: %s, error: %s", query, err)
	default:
		if userName != nil {
			userAttributes["userName"] = string(userName.([]uint8))
		}
		if firstName != nil {
			userAttributes["firstName"] = string(firstName.([]uint8))
		}
		if lastName != nil {
			userAttributes["lastName"] = string(lastName.([]uint8))
		}
		if caption != nil {
			userAttributes["caption"] = string(caption.([]uint8))
		}
		if phoneNumber != nil {
			userAttributes["phoneNumber"] = string(phoneNumber.([]uint8))
		}

		sa.logger.Info("found user attributes", zap.Any("user_attributes", userAttributes), zap.Int("user_id", userID))
	}
	return userAttributes, nil
}

// GetUserClaims returns user claims.
func (sa *Authenticator) GetUserClaims(userID int) (map[string]string, error) {
	userClaims := make(map[string]string)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT claimType, claimValue FROM UserClaims WHERE userId = ?"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, userID)
	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("no claims not found")
	case err != nil:
		return nil, fmt.Errorf("sqlite3 database query failed: %s, error: %s", query, err)
	}
	if rows == nil {
		return nil, fmt.Errorf("no claims not found, rows nil")
	}
	for rows.Next() {
		var claimType, claimValue string
		if err := rows.Scan(&claimType, &claimValue); err != nil {
			return nil, fmt.Errorf("sqlite3 database rows scan failed: %s", err)
		}
		userClaims[claimType] = claimValue
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("sqlite3 database rows close failed: %s", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite3 database rows scan erred: %s", err)
	}

	sa.logger.Info("found user claims", zap.Any("user_attributes", userClaims), zap.Int("user_id", userID))

	return userClaims, nil
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
	requiredTables := []string{"Users", "UserClaims"}
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
	query := "SELECT count(id) FROM Users"
	stmt, err := sa.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query sqlite3 database: %s, error: %s", query, err)
	}
	defer stmt.Close()
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

// AuthenticateUser checks the database for the presence of a username/email
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(userInput, password string) (*jwt.UserClaims, int, error) {
	sa.mux.Lock()
	defer sa.mux.Unlock()

	if strings.Contains(userInput, "@") {
		// Check whether the email exists.
		userCount, err := sa.GetUserEmailCount(userInput)
		if err != nil {
			return nil, 500, err
		}
		if userCount != 1 {
			return nil, 401, fmt.Errorf("user identity not found")
		}
	} else {
		// Check whether the username exists.
		userCount, err := sa.GetUserNameCount(userInput)
		if err != nil {
			return nil, 500, err
		}
		if userCount != 1 {
			return nil, 401, fmt.Errorf("user identity not found")
		}
	}

	// Authenticate the user
	userID, passwordHash, userEmail, err := sa.GetUserID(userInput)
	if err != nil {
		return nil, 500, fmt.Errorf("failed getting user id")
	}
	if userID == 0 {
		return nil, 401, fmt.Errorf("authentication failed")
	}
	if userEmail == "" {
		return nil, 500, fmt.Errorf("failed getting user id")
	}
	// Compare password hashes
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, 401, fmt.Errorf("authentication failed due to password hash mismatch")
	}

	// Get user attributes
	userAttributes, err := sa.GetUserAttributes(userID)
	if err != nil {
		return nil, 500, fmt.Errorf("failed getting user attributes, error: %s", err)
	}
	if userAttributes == nil {
		return nil, 500, fmt.Errorf("failed getting user attributes, attributes nil")
	}

	// Get user claims
	userClaims, err := sa.GetUserClaims(userID)
	if err != nil {
		return nil, 500, fmt.Errorf("failed getting user claims, error: %s", err)
	}
	if userClaims == nil {
		return nil, 500, fmt.Errorf("failed getting user claims, claims nil")
	}

	claims := &jwt.UserClaims{}
	claims.Subject = userEmail
	claims.Email = userEmail

	if _, firstNameExists := userAttributes["firstName"]; firstNameExists {
		if _, lastNameExists := userAttributes["lastName"]; lastNameExists {
			if userAttributes["firstName"] != "" && userAttributes["lastName"] != "" {
				claims.Name = userAttributes["firstName"] + " " + userAttributes["lastName"]
			}
		}
	}

	if _, userNameExists := userAttributes["userName"]; userNameExists {
		if userAttributes["userName"] != "" {
			claims.Subject = userAttributes["userName"]
		}
	}

	for k, v := range userClaims {
		if v == "" {
			continue
		}
		switch k {
		case "roles":
			for _, item := range strings.Split(v, " ") {
				claims.Roles = append(claims.Roles, item)
			}
		case "org":
			for _, item := range strings.Split(v, " ") {
				claims.Organizations = append(claims.Organizations, item)
			}
		}
	}

	return claims, 200, nil
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
		userName := uuid.New().String()[:8]
		userPwd := uuid.New().String()[:8]
		if len(userName) < 8 || len(userPwd) < 8 {
			return fmt.Errorf("failed to create default superadmin user")
		}
		userClaims := make(map[string]interface{})
		userClaims["roles"] = "internal/superadmin"
		userClaims["org"] = "internal"
		userEmail := userName + "@localdomain.local"
		if err := b.Authenticator.CreateUser(userName, userPwd, userEmail, userClaims); err != nil {
			b.logger.Error("failed to create default superadmin user for the database",
				zap.String("error", err.Error()))
			return err
		}
		b.logger.Info("created default superadmin user for the database",
			zap.String("user_name", userName),
			zap.String("user_secret", userPwd),
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
