package permit.abac

import future.keywords.in

import data.permit.generated.conditionset
import data.permit.generated.abac.utils as utils

default allow := false


allow {
        some value in matching_users_and_resources_set
        is_allowing_pair(value.user, value.resource)
}

allowing_rules := {
   {"userset": userset, "resourceset": resourceset} |
   some val in matching_users_and_resources_set
    userset := val.user
    resourceset := val.resource
}

get_decoded_condition_set_key(key_input) := result {
    some key, value in data.condition_sets
    value.key == key_input
    result := key
}

get_encoded_condition_set_key(key_input) := result {
    result := data.condition_sets[key_input].key
}

get_resource_set_keys(resource_set_value) = {result |
    some re_key, _ in resource_set_value
    result := get_decoded_condition_set_key(re_key)
}

# Rule Description: action_exist_or_action_not_required rule help to support authorized_user rule and user_permissions rule.
# Both rules used matching_users_and_resources_set (that use get_condition_set_keys),
# authorized_user aim is to find the actions user is allowed to perform so  input.action
# will be undefined.
# user_permissions input has action and we used to filter un relevant results to improve performance.
# so we need to support to cases one without checking if action is exist in condition_set_rules
# for authorized_user and another case for user_permissions that check if the action provided in
# the input.action match to the actions that in condition_set_rules
action_exist_or_action_not_required(key,resource_set_key) {
	not input.action
} else {
	 actions := data.condition_set_rules[key][resource_set_key][input.resource.type]
     input.action in actions
}


get_condition_set_keys[user_set_key] := value {
        some key , resource_set_value in data.condition_set_rules
            some resource_set_key, resource_set_data in resource_set_value
				action_exist_or_action_not_required(key,resource_set_key)
                user_set_key := get_decoded_condition_set_key(key)
                value := get_resource_set_keys(resource_set_value)
}

matching_users_and_resources_set := result {
    data.condition_set_rules_expand
    count(data.condition_set_rules_expand) > 0
    result := matching_users_and_resources_set_from_condition_set_rules_expand
} else = result {
    result := matching_users_and_resources_set_from_condition_set_rules
}

matching_users_and_resources_set_from_condition_set_rules := {
    {"user": op_us, "resource": op_rs} |

    some key, value in get_condition_set_keys
        conditionset[key] == true
        op_us := get_encoded_condition_set_key(key)
        some r_key, r_value in value
                conditionset[r_key] == true
                op_rs := get_encoded_condition_set_key(r_key)
}

matching_users_and_resources_set_from_condition_set_rules_expand := {
    {"user": op_us, "resource": op_rs} |

    some key, value in data.condition_set_rules_expand
        conditionset[key] == true
        op_us := key
        some r_key, r_value in value
                conditionset[r_key] == true
                op_rs := r_key
}

is_allowing_pair(userset, resourceset) {
    # get the permissions in this couple of userset <> resourceset
    permissions := utils.condition_set_permissions[userset][resourceset][input.resource.type]

    # check if the specified action is allowed in this couple of userset <> resourceset
    input.action in permissions
}

decode_condition_set_key(key) = value {
    value := data.condition_sets[key].key
} else = key {
    true
}

# Deprecated
matching_usersets[userset] {
    some set, value in conditionset
    value == true
    userset := decode_condition_set_key(set)
}

#Deprecated
matching_resourcesets[resourceset] {
    some set, value in conditionset
    value == true
    resourceset := decode_condition_set_key(set)
}

usersets[set] {
    some _set, _ in conditionset
    set := decode_condition_set_key(_set)
}

resourcesets[set] {
    some _set, _ in conditionset
    set := decode_condition_set_key(_set)
}

default activated := false

# If there are any usersets or resourcesets, then abac is activated
activated {
    count(usersets) > 0
}

activated {
    count(resourcesets) > 0
}