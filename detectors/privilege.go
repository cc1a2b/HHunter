package detectors

import (
	"encoding/json"
	"strings"

	"github.com/cc1a2b/hhunter/engine"
)

type PrivilegeDetector struct{}

func NewPrivilegeDetector() *PrivilegeDetector {
	return &PrivilegeDetector{}
}

func (d *PrivilegeDetector) Detect(baseline, mutated *engine.ResponseContext) bool {
	baselinePriv := d.extractPrivilegeLevel(baseline)
	mutatedPriv := d.extractPrivilegeLevel(mutated)

	if mutatedPriv > baselinePriv {
		return true
	}

	if d.hasAdminContent(mutated) && !d.hasAdminContent(baseline) {
		return true
	}

	return false
}

func (d *PrivilegeDetector) extractPrivilegeLevel(resp *engine.ResponseContext) int {
	body := strings.ToLower(string(resp.Body))

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err == nil {
		if role, ok := data["role"].(string); ok {
			return d.getRoleLevel(role)
		}
		if isAdmin, ok := data["isAdmin"].(bool); ok && isAdmin {
			return 3
		}
		if admin, ok := data["admin"].(bool); ok && admin {
			return 3
		}
	}

	if strings.Contains(body, "administrator") || strings.Contains(body, "superuser") {
		return 3
	}
	if strings.Contains(body, "admin") {
		return 2
	}
	if strings.Contains(body, "user") {
		return 1
	}

	return 0
}

func (d *PrivilegeDetector) getRoleLevel(role string) int {
	role = strings.ToLower(role)
	switch role {
	case "admin", "administrator", "superuser", "root":
		return 3
	case "moderator", "manager":
		return 2
	case "user", "member":
		return 1
	default:
		return 0
	}
}

func (d *PrivilegeDetector) hasAdminContent(resp *engine.ResponseContext) bool {
	body := strings.ToLower(string(resp.Body))

	adminIndicators := []string{
		"admin panel",
		"administrator",
		"admin dashboard",
		"user management",
		"system settings",
		"delete user",
		"manage users",
	}

	for _, indicator := range adminIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

func (d *PrivilegeDetector) DetectRoleChange(baseline, mutated *engine.ResponseContext) (string, string) {
	baselineRole := d.extractRole(baseline)
	mutatedRole := d.extractRole(mutated)

	return baselineRole, mutatedRole
}

func (d *PrivilegeDetector) extractRole(resp *engine.ResponseContext) string {
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err == nil {
		if role, ok := data["role"].(string); ok {
			return role
		}
	}

	body := strings.ToLower(string(resp.Body))
	if strings.Contains(body, "admin") {
		return "admin"
	}
	if strings.Contains(body, "user") {
		return "user"
	}

	return "unknown"
}

func (d *PrivilegeDetector) GetEvidence(baseline, mutated *engine.ResponseContext) map[string]string {
	evidence := make(map[string]string)

	baselineRole, mutatedRole := d.DetectRoleChange(baseline, mutated)
	if baselineRole != mutatedRole {
		evidence["role_change"] = baselineRole + " -> " + mutatedRole
	}

	if d.hasAdminContent(mutated) && !d.hasAdminContent(baseline) {
		evidence["admin_content_exposed"] = "true"
	}

	baselinePriv := d.extractPrivilegeLevel(baseline)
	mutatedPriv := d.extractPrivilegeLevel(mutated)
	if mutatedPriv > baselinePriv {
		evidence["privilege_escalation"] = "true"
	}

	return evidence
}
