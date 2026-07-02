module github.com/myguard-labs/gyzor

go 1.24

require golang.org/x/net v0.38.0

require golang.org/x/text v0.23.0 // indirect

// Versions v1.0.0–v1.1.0 were published under the old module path
// github.com/eilandert/gyzor. Under the new path they are invalid.
retract (
	v1.1.0
	v1.0.0
)
