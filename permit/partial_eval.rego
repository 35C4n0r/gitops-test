package permit.partial_eval

import future.keywords.contains
import future.keywords.in

default allow := false

allow {
	checked_permission := sprintf("%s:%s", [input.resource.type, input.action])

	some granting_role, role_data in data.roles
	some resource_type, actions in role_data.grants
	granted_action := actions[_]
	granted_permission := sprintf("%s:%s", [resource_type, granted_action])

	some tenant, roles in data.users[input.user.key].roleAssignments
	role := roles[_]
	role == granting_role
	checked_permission == granted_permission
	input.resource.tenant == tenant
}