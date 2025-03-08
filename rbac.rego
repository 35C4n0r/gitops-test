
package permit.rbac

import future.keywords

default use_factdb := false
use_factdb := input.context.use_factdb

default user_identifier := ""
default tenant_identifier := ""
user_identifier := sprintf("user:%s",[input.user.key])
tenant_identifier := sprintf("__tenant:%s",[input.resource.tenant])

# By default, deny requests.
default allow := false

# Allow the action if the user is granted permission to perform the action.
allow {
	count(matching_grants) > 0
}

matching_grants[grant] {
	# Find grants for the user.
	some grant in grants

	# Check if the grant permits the action.
	input.action == grant
}

tenant := tenant_key {
	input.resource.tenant != null
	tenant_key := input.resource.tenant
}

user_roles[role_key] {
  use_factdb
	some role_key in input.context.data.role_assignments[user_identifier][tenant_identifier]
}

user_roles[role_key] {
  not use_factdb
  some role_key in data.users[input.user.key].roleAssignments[tenant]
}

default roles_resource := "__tenant"

roles_resource := data.roles_resource

grants[grant] {
	some role_key in user_roles
	some grant in data.role_permissions[roles_resource][role_key].grants[input.resource.type]
}

allowing_roles[role_key] {
	some role_key in user_roles
	input.action in data.role_permissions[roles_resource][role_key].grants[input.resource.type]
}

