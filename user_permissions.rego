package permit.user_permissions


import data.permit.abac_user_permissions


import future.keywords.in


user := sprintf("user:%s", [input.user.key])

user_assignments := data.role_assignments[user]

__input_tenants := object.get(input, "tenants", null)

__input_resources := object.get(input, "resources", null)

__input_resource_types := object.get(input, "resource_types", null)

__tenant_type := {"resource_type": "__tenant"}

split_resource_role_to_parts(resource_role) := parts_details {
	parts := split(resource_role, "#")
	count(parts) == 2
	resource := parts[0]
	role := parts[1]
	parts_details := {
		"resource": split_resource_to_parts(resource),
		"role": role,
	}
}

split_resource_to_parts(resource) := parts_details {
	parts := split(resource, ":")
	count(parts) == 2
	resource_type := parts[0]
	resource_instance := parts[1]
	fully_qualified_key := resource
	parts_details := {
		"fully_qualified_key": fully_qualified_key,
		"resource_type": resource_type,
		"resource_instance": resource_instance,
	}
} else {
	resource_type := "__tenant"
	resource_instance := resource
	fully_qualified_key := sprintf("%s:%s", [resource_type, resource_instance])
	parts_details := {
		"fully_qualified_key": fully_qualified_key,
		"resource_type": resource_type,
		"resource_instance": resource_instance,
	}
}

non_tenant_instances_filter[inst] {
	inst := __input_resources[_]
	not startswith(inst, __tenant_type.resource_type)
}

default has_instances_filter := false

has_instances_filter {
	count(non_tenant_instances_filter) > 0
}

is_filtered_resource_type(resource) {
	is_array(__input_resource_types)
	resource.resource_type in __input_resource_types
} else {
	not is_array(__input_resource_types)
}

_is_filtered_tenant(resource) {
	resource.fully_qualified_key in __input_tenants
} else {
	resource.resource_instance in __input_tenants
}
  else {
	resource.tenant in __input_tenants
}
 else {
	__input_tenants == null
}

is_filtered_tenant(resource) {
	is_filtered_resource_type(__tenant_type)
	is_array(__input_tenants)
	_is_filtered_tenant(resource)
} else {
	# backwards compatibility with sidecar input manipulation
	is_filtered_resource_type(__tenant_type)
	is_array(__input_resources)
	resource.fully_qualified_key in __input_resources
} else {
	is_filtered_resource_type(__tenant_type)
	not is_array(__input_tenants)

	# backwards compatibility with sidecar input manipulation
	not is_array(__input_resources)
}

is_filtered_instance(resource) {
	is_filtered_resource_type(resource)
	is_array(__input_resources)
	resource.fully_qualified_key in __input_resources
} else {
	is_filtered_resource_type(resource)
	is_array(__input_resources)
	resource.resource_instance in __input_resources
} else {
	is_filtered_resource_type(resource)
	not is_array(__input_resources)
}

# this is needed for backwards compatibility with older PDPs
# that inject tenants into the resource instances filter
is_filtered_resource(resource) {
	resource.resource_type == __tenant_type.resource_type
	is_filtered_tenant(resource)
} else {
	# meaning: all instances should be allowed because there was
	# no filter on specific instance keys (no "resources" filter)
	not has_instances_filter

	# we still have to filter by resource types if this filter exists
	is_filtered_resource_type(resource)
} else {
	is_filtered_instance(resource)
}

build_permissions_object(resource_object_key, resource_type, resource_key, resource_attributes, resource_permissions, roles) := {
	sprintf("%s:%s",[resource_type,resource_key]): {
		resource_object_key: {
			"key": resource_key,
			"type": resource_type,
			"attributes": resource_attributes,
		},
		"permissions": resource_permissions,
		"roles": roles,
	}
}

roles_permissions(role_assignments, resource_details) := {sprintf("%s:%s", [resource, permission]) |
	# iterate role assignments
	role := role_assignments[_]

	# extract role permission grants
	role_permissions_map := data.role_permissions[resource_details.resource_type][role].grants

	# iterate role permissions grants on each resource
	resource_permissions := role_permissions_map[resource]

	# extract permission grants
	permission := resource_permissions[_]
}

remove_built_in_roles(roles) := filtered_roles {
	filtered_roles := [role | role := roles[i]; role != "tenant-association"]
}

default __rebac_roles := {}



__rebac_roles := permit_rebac.all_roles(input)




# aggregate all properties with property key 'prop' from object 'obj' with key 'key'
agg_values(key, obj, prop) := value {
    value := [p |
        p := obj[key][prop][_]
    ]
}


# helper rule to get the related tenant
get_tenant(key) := result {
	# if key belong to rbac_permissoins
    rbac_permissions[key].tenant != null
    result := rbac_permissions[key].tenant
} else =  result {
	# if key belong to abac_permissions
    abac_permissions[key].tenant != null
    result := abac_permissions[key].tenant
} else = result {
	# if key belong to rebac_permissions
    rebac_permissions[key].tenant != null
    result := rebac_permissions[key].tenant
}

else = result {
	# if key belong to abac_permissions and the result based on resource instance
	data.resource_instances[key].tenant != null
    result := object.union(data.tenants[data.resource_instances[key].tenant], {"key": data.resource_instances[key].tenant, "type": "__tenant"})
}


concat_three_arrays(arr_1,arr_2,arr_3) := result {
    result := array.concat(array.concat(arr_1, arr_2), arr_3)
}

# get all the permissions from rbac_permissions, abac_permissions and rebac_permissions and union them but without to override their properties
# but instead aggregate them (different from rego object.union and object.union_n)
permissions[key] := result {
    unique_keys := object.keys(object.union_n([
        rbac_permissions,
        rebac_permissions,
        abac_permissions,
    ]))

    some key in unique_keys
	    # aggregate all the common permissions of the key
        permissions_rbac := agg_values(key,rbac_permissions, "permissions")
        permissions_abac := agg_values(key,abac_permissions, "permissions")
        permissions_rebac := agg_values(key,rebac_permissions, "permissions")

		# aggregate all the common roles of the key
        roles_rbac := agg_values(key,rbac_permissions, "roles")
        roles_abac := agg_values(key,abac_permissions, "roles")
        roles_rebac := agg_values(key,rebac_permissions, "roles")

		# generate result with the form {"key" :{ "permissions": aggregated_permissions, "roles": aggregated_roles}, "tenant": related_tenant}
         _result := {
			"permissions": concat_three_arrays(permissions_rbac, permissions_abac, permissions_rebac),
			"roles": concat_three_arrays(roles_rbac, roles_abac, roles_rebac ),
			"tenant": get_tenant(key)
		}

		result := object.union(
			_result,
			get_resource(key)
		)
}

get_resource(key) := result {
	result := { "resource": rebac_permissions[key].resource}
} else  := result  {
	result := { "resource": rbac_permissions[key].resource}
} else := result  {
	result := { "resource": abac_permissions[key].resource}
} else := result {
	result := {}
}

default rbac_permissions := {}

rbac_permissions := object.union_n([v | v := _rbac_permissions[_]])

default rebac_permissions := {}

rebac_permissions := object.union_n([v | v := _rebac_permissions[_]])

default abac_permissions := {}




get_all_abac_permissions(key) := permissions {
    permissions := {p |
        some entry in _abac_permissions
        p := entry[key].permissions[_]
	}
}

_abac_permissions_unique_keys := {key: tenant |
    some obj in _abac_permissions
        key := object.keys(obj)[_]
        tenant := obj[key].tenant
}



agg_abac_permissions := {result |
    some key,tenant in _abac_permissions_unique_keys
        result := {
			key: {
				"permissions": get_all_abac_permissions(key),
				"tenant": tenant
			}
		}
}

abac_permissions := object.union_n([v | v := agg_abac_permissions[_]])


_rbac_permissions[object_permissions] {
	some assigned_object, _ in user_assignments
	startswith(assigned_object, "__tenant:")
	object_permissions := __rbac_permissions[assigned_object]
}

flattened_role_permissions[role_key] := grants {
	some role_key
	resource_permissions := data.role_permissions.__tenant[role_key].grants
	grants := [sprintf("%s:%s", [resource, action]) |
		permissions := resource_permissions[resource]
		action := permissions[_]
	]
}

__rbac_permissions[assigned_object] := build_permissions_object(
	"tenant",
	"__tenant",
	tenant_key,
	object.get(tenant_obj, "attributes", {}),
	permissions,
	roles,
) {
	assigned_roles := user_assignments[assigned_object]
	roles := remove_built_in_roles(assigned_roles)

	tenant_details := split_resource_to_parts(assigned_object)

	is_filtered_tenant(tenant_details)
	tenant_key := tenant_details.resource_instance

	tenant_obj := data.tenants[tenant_key]

	# aggregate precalculated role permissions for each of the user's roles
	permissions := {permission |
		role := roles[_]
		permission := flattened_role_permissions[role][_]
	}
}


_rebac_permissions[resource] := build_permissions_object(
	"resource",
	resource_details.resource_type,
	resource_details.resource_instance,
	object.get(resource_obj, "attributes", {}),
	permissions,
	stripped_roles,
) {
	rebac_all_roles := __rebac_roles
	some resource, roles in rebac_all_roles
	resource_obj := object.get(data.resource_instances, resource, {})
	resource_details := split_resource_to_parts(resource)
	updated_resource_details := object.union(resource_details,
	{"tenant": object.get(resource_obj,"tenant","")})
	is_filtered_resource(updated_resource_details)
	_is_filtered_tenant(updated_resource_details)
	stripped_roles := [stripped_role |
		role := roles[_]
		stripped_role := split_resource_role_to_parts(role).role
	]
	permissions := roles_permissions(stripped_roles, resource_details)
}



_abac_permissions[p] {
    input.context.enable_abac_user_permissions
	p := abac_user_permissions.permissions[_]
}


tenants[tenant] {
	some assigned_object, _ in user_assignments
	startswith(assigned_object, "__tenant:")
	tenant_details := split_resource_to_parts(assigned_object)
	tenant_key := tenant_details.resource_instance
	tenant := object.union(
		object.get(data.tenants, tenant_key, {}),
		{"key": tenant_key},
	)
}