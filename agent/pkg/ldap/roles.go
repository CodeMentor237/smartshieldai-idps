package ldap

import (
	"fmt"
	"strings"
)

// Role represents a normalized user role
type Role struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Level       int      `json:"level"` // Higher number means more privileges
}

// RoleNormalizer normalizes user roles across different platforms
type RoleNormalizer struct {
	roleMappings map[string]Role
}

// NewRoleNormalizer creates a new role normalizer
func NewRoleNormalizer() *RoleNormalizer {
	return &RoleNormalizer{
		roleMappings: map[string]Role{
			// Windows AD roles
			"Domain Admins": {
				Name:        "administrator",
				Description: "Full system administrator",
				Permissions: []string{"*"},
				Level:       100,
			},
			"Enterprise Admins": {
				Name:        "administrator",
				Description: "Full system administrator",
				Permissions: []string{"*"},
				Level:       100,
			},
			"Schema Admins": {
				Name:        "administrator",
				Description: "Full system administrator",
				Permissions: []string{"*"},
				Level:       100,
			},
			"Domain Users": {
				Name:        "user",
				Description: "Standard user",
				Permissions: []string{"read", "execute"},
				Level:       10,
			},
			"Guests": {
				Name:        "guest",
				Description: "Limited access user",
				Permissions: []string{"read"},
				Level:       1,
			},

			// Linux/Unix roles
			"root": {
				Name:        "administrator",
				Description: "Full system administrator",
				Permissions: []string{"*"},
				Level:       100,
			},
			"sudo": {
				Name:        "power_user",
				Description: "User with elevated privileges",
				Permissions: []string{"read", "write", "execute", "sudo"},
				Level:       50,
			},
			"wheel": {
				Name:        "power_user",
				Description: "User with elevated privileges",
				Permissions: []string{"read", "write", "execute", "sudo"},
				Level:       50,
			},
			"users": {
				Name:        "user",
				Description: "Standard user",
				Permissions: []string{"read", "execute"},
				Level:       10,
			},
			"nobody": {
				Name:        "guest",
				Description: "Limited access user",
				Permissions: []string{"read"},
				Level:       1,
			},
		},
	}
}

// NormalizeRole normalizes a role name to a standard format
func (n *RoleNormalizer) NormalizeRole(roleName string) (Role, error) {
	// Convert to lowercase for case-insensitive matching
	roleName = strings.ToLower(roleName)

	// Try exact match first
	if role, ok := n.roleMappings[roleName]; ok {
		return role, nil
	}

	// Try case-insensitive match
	for k, v := range n.roleMappings {
		if strings.ToLower(k) == roleName {
			return v, nil
		}
	}

	// Try partial match
	for k, v := range n.roleMappings {
		if strings.Contains(strings.ToLower(k), roleName) {
			return v, nil
		}
	}

	// Default to standard user if no match found
	return Role{
		Name:        "user",
		Description: "Standard user",
		Permissions: []string{"read", "execute"},
		Level:       10,
	}, nil
}

// AddRoleMapping adds a custom role mapping
func (n *RoleNormalizer) AddRoleMapping(roleName string, role Role) {
	n.roleMappings[roleName] = role
}

// GetRoleLevel returns the privilege level of a role
func (n *RoleNormalizer) GetRoleLevel(roleName string) (int, error) {
	role, err := n.NormalizeRole(roleName)
	if err != nil {
		return 0, fmt.Errorf("failed to normalize role: %v", err)
	}
	return role.Level, nil
}

// HasPermission checks if a role has a specific permission
func (n *RoleNormalizer) HasPermission(roleName, permission string) (bool, error) {
	role, err := n.NormalizeRole(roleName)
	if err != nil {
		return false, fmt.Errorf("failed to normalize role: %v", err)
	}

	// Check for wildcard permission
	for _, p := range role.Permissions {
		if p == "*" {
			return true, nil
		}
		if p == permission {
			return true, nil
		}
	}

	return false, nil
} 