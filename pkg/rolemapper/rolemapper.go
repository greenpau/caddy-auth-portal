package rolemapper

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"time"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"

	"go.uber.org/zap"
)

// RoleMap stores each role mapping data loaded from the conf
type RoleMap struct {
	Email  string   `json:"email,omitempty"`
	Match  string   `json:"match,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Realms []string `json:"realms,omitempty"` // if set, then only apply this mapper to the specified realms/backends.
}

type implInterface interface {
	GetRoleMap() ([]RoleMap, error)
}

// StaticImpl contains a fixed list of RoleMaps
type StaticImpl struct {
	RoleMapping []RoleMap `json:"users,omitempty"`
}

// GetRoleMap returns the list of RoleMaps
func (impl StaticImpl) GetRoleMap() ([]RoleMap, error) {
	return impl.RoleMapping, nil
}

// FileImpl contains a list of RoleMaps loaded from files
type FileImpl struct {
	RoleMappingPaths []string `json:"paths,omitempty"`
	loadedFileTimes  []time.Time

	mappingCache []StaticImpl
	Logger       *zap.Logger
}

// LoadFromFile will load the RoleMap conf from for the specified file (idx) into its rolemap cache list
func (impl *FileImpl) LoadFromFile(idx int) error {
	path := impl.RoleMappingPaths[idx]
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("failed to create local database file at %s: %s", path, err)
		}
		return fmt.Errorf("failed obtaining information about local database file at %s: %s", path, err)
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("local database file path points to a directory")
	}

	if impl.loadedFileTimes[idx] == fileInfo.ModTime() {
		return nil
	}

	impl.loadedFileTimes[idx] = fileInfo.ModTime()

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var m []RoleMap
	err = json.Unmarshal(content, &m)
	if err != nil {
		return err
	}
	impl.mappingCache[idx].RoleMapping = m
	return nil
}

// GetRoleMap returns the list of RoleMaps loaded from files - will reload if the file changed
func (impl *FileImpl) GetRoleMap() ([]RoleMap, error) {
	var allRoleMaps []RoleMap
	for idx, path := range impl.RoleMappingPaths {
		if err := impl.LoadFromFile(idx); err != nil {
			impl.Logger.Error("loading file based rolemap",
				zap.String("path", path),
				zap.Error(err),
			)
			continue
		}

		m, err := impl.mappingCache[idx].GetRoleMap()
		if err != nil {
			impl.Logger.Error("calling GetRoleMap",
				zap.String("path", path),
				zap.Error(err),
			)
		}
		allRoleMaps = append(allRoleMaps, m...)
	}

	return allRoleMaps, nil
}

// RoleMapper holds all the role mappers for an AuthPortal
type RoleMapper struct {
	Impls []implInterface

	Logger *zap.Logger
}

// AddStaticImpl adds a new Static RoleMapper from a list of RoleMaps
func (r *RoleMapper) AddStaticImpl(m []RoleMap) {
	r.Impls = append(r.Impls, StaticImpl{
		RoleMapping: m,
	})
}

// AddFileImpl adds a new File based RoleMapper from a list of paths
func (r *RoleMapper) AddFileImpl(p []string) {
	r.Impls = append(r.Impls, &FileImpl{
		RoleMappingPaths: p,
		loadedFileTimes:  make([]time.Time, len(p)),
		mappingCache:     make([]StaticImpl, len(p)),
		Logger:           r.Logger,
	})
}

// UnmarshalJSON unpacks configuration into appropriate structures.
func (r *RoleMapper) UnmarshalJSON(data []byte) error {
	var confData map[string]interface{}
	if err := json.Unmarshal(data, &confData); err != nil {
		return fmt.Errorf("failed to unpack RoleMapper configuration data: %s", data)
	}

	if _, exists := confData["Impls"]; !exists || confData["Impls"] == nil {
		return nil
	}
	implData, ok := confData["Impls"].([]interface{})
	if !ok {
		return fmt.Errorf("type assertion of Impl failed: %v", confData["Impls"])
	}

	for _, m := range implData {
		mapper, ok := m.(map[string]interface{})
		if !ok {
			return fmt.Errorf("type assertion of mapper failed: %v", m)
		}

		if v, exists := mapper["paths"]; exists {
			b, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("Marshal of paths failed: %v\nError: %s", v, err)
			}
			var paths []string
			if err := json.Unmarshal(b, &paths); err != nil {
				return fmt.Errorf("failed to unpack usermap data: %s", b)
			}

			r.AddFileImpl(paths)
		}
		if v, exists := mapper["users"]; exists {
			b, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("Marshal of users failed: %v\nError: %s", v, err)
			}
			var usermap []RoleMap
			if err := json.Unmarshal(b, &usermap); err != nil {
				return fmt.Errorf("failed to unpack usermap data: %s", b)
			}

			r.AddStaticImpl(usermap)
		}
	}

	return nil
}

// ApplyRoleMapToClaims adds roles from the rolemappings to the authenticated user's claim
func (r *RoleMapper) ApplyRoleMapToClaims(claims *jwtclaims.UserClaims, realm string) {
	for _, impl := range r.Impls {
		implRoleMap, err := impl.GetRoleMap()
		if err != nil {
			r.Logger.Error("Failed to GetRoleMap from %s: %s", zap.Any("impl", impl), zap.Error(err))
			continue
		}
		r.Logger.Debug("GetRoleMap", zap.Any("impl", impl), zap.Any("roles", implRoleMap))

		applyRoleMapToClaims(implRoleMap, claims, realm)
	}
}

func applyRoleMapToClaims(rm []RoleMap, claims *jwtclaims.UserClaims, realm string) {
	if len(rm) < 1 {
		return
	}

	userID := claims.Email
	if userID == "" {
		// the github oauth2 case...
		userID = claims.Subject
	}
	if userID == "" {
		return
	}

	roles := []string{}
	roleMap := make(map[string]interface{})
	for _, roleName := range claims.Roles {
		roleMap[roleName] = true
		roles = append(roles, roleName)
	}

	for _, entry := range rm {
		// used to support the backend specific rolemappers (for eg, the original oauth2 code)
		if len(entry.Realms) > 0 {
			skip := true
			for _, v := range entry.Realms {
				if v == realm {
					skip = false
				}
			}
			if skip {
				continue
			}
		}

		entryEmail := entry.Email
		entryMatchType := entry.Match

		switch entryMatchType {
		case "regex":
			// Perform regex match
			matched, err := regexp.MatchString(entryEmail, userID)
			if err != nil {
				continue
			}
			if !matched {
				continue
			}
		case "exact":
			// Perform exact match
			if entryEmail != userID {
				continue
			}
		default:
			continue
		}
		entryRoles := entry.Roles
		for _, r := range entryRoles {
			roleName := r
			if _, exists := roleMap[roleName]; !exists {
				roleMap[roleName] = true
				roles = append(roles, roleName)
			}
		}
	}
	claims.Roles = roles
}
