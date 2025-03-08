package permit.bulk

import data.permit.root

default allow := []

allow := results {
	checks = input.checks
	results := [result |
		check := checks[_]
        check_input := object.union(check, {"use_debugger": root.__input_use_debugger})
		result := root with input as check_input
	]
}