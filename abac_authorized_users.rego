package permit.abac_authorized_users

import data.permit.abac as abac
import data.permit.generated.abac.utils
import data.permit.generated.conditionset
import future.keywords.if
import future.keywords.in


default use_factdb := false
use_factdb := input.context.use_factdb

abac_authorized_users[user] := roles if {
    some user, user_data in input.context.data.users

    customize_input := {
        "action": input.action,
        "user" :  {"key": user},
        "resource" : input.resource,
    }

        user_resource_pairs := abac.matching_users_and_resources_set with input as customize_input
        roles := { { "user": user, "role":user_resource_pair.user, "resource" : user_resource_pair.resource , "tenant" : input.resource.tenant} |
            some user_resource_pair in user_resource_pairs }
        count(roles) > 0
}
