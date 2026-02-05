// Package policycheck provides a generic policy checking framework for ConnectRPC services.
// It allows services to register custom policy handlers and automatically execute them
// based on generated policy maps.
package policycheck

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
)

// PolicyProvider is an interface that all generated policy structures must implement.
// It allows the checker to access policies without using reflection.
type PolicyProvider interface {
	// GetPolicies returns all policy instances contained in this provider.
	// Each policy is returned as an interface{} and should be type-asserted
	// by the corresponding policy handler.
	GetPolicies() []any
}

// Handler is a function that checks a specific policy type.
// It receives the policy data as any and should perform type assertion
// to convert it to the actual policy type defined in the service's proto.
//
// Example:
//
//	handler := func(ctx context.Context, policy any, req connect.AnyRequest) error {
//	    perm := policy.(*myservice.Permission)
//	    return checkPermission(req, perm.Required)
//	}
type Handler func(ctx context.Context, policy any, req connect.AnyRequest) error

// Checker is the core policy checking engine.
// It maintains a registry of policy handlers and provides methods to
// execute policies against incoming requests.
type Checker struct {
	handlers map[string]Handler
}

// New creates a new Checker instance.
func New() *Checker {
	return &Checker{
		handlers: make(map[string]Handler),
	}
}

// Register registers a handler for a specific policy type.
// The typeName should match the generated policy type name (e.g., "Permission", "RateLimit").
//
// Example:
//
//	checker.Register("Permission", func(ctx context.Context, policy any, req connect.AnyRequest) error {
//	    perm := policy.(*userv1.Permission)
//	    return validatePermission(req, perm.Required)
//	})
func (c *Checker) Register(typeName string, handler Handler) {
	c.handlers[typeName] = handler
}

// Check executes all registered handlers for the given policies.
// It calls the PolicyProvider.GetPolicies() method to retrieve all policies
// and then invokes the corresponding handler for each policy based on its type.
//
// The policies parameter must implement the PolicyProvider interface.
//
// Returns the first error encountered, or nil if all checks pass.
func (c *Checker) Check(ctx context.Context, policies any, req connect.AnyRequest) error {
	if policies == nil {
		return nil
	}

	// Check if policies implements PolicyProvider interface
	provider, ok := policies.(PolicyProvider)
	if !ok {
		return fmt.Errorf("policies must implement PolicyProvider interface, got %T", policies)
	}

	// Get all policies from the provider (no reflection needed!)
	policyList := provider.GetPolicies()

	// Iterate through each policy
	for _, policy := range policyList {
		if policy == nil {
			continue
		}

		// Get the type name using simple type switching
		typeName := c.getPolicyTypeName(policy)
		if typeName == "" {
			continue
		}

		// Look up the handler
		handler, exists := c.handlers[typeName]
		if !exists {
			// No handler registered for this policy type, skip
			continue
		}

		// Execute the handler
		if err := handler(ctx, policy, req); err != nil {
			return fmt.Errorf("policy check failed for %s: %w", typeName, err)
		}
	}

	return nil
}

// getPolicyTypeName extracts the type name from a policy instance.
// This uses a simple type assertion approach rather than reflection.
// The policy types are expected to be concrete struct pointers.
func (c *Checker) getPolicyTypeName(policy any) string {
	// We use fmt.Sprintf with %T to get the type name, then extract the actual name
	// This is still technically using some reflection under the hood, but it's much lighter
	// than the previous field iteration approach.
	typeName := fmt.Sprintf("%T", policy)

	// Remove the pointer prefix and package path
	// e.g., "*user.Permission" -> "Permission"
	if len(typeName) > 0 && typeName[0] == '*' {
		typeName = typeName[1:]
	}

	// Find the last dot and take everything after it
	for i := len(typeName) - 1; i >= 0; i-- {
		if typeName[i] == '.' {
			return typeName[i+1:]
		}
	}

	return typeName
}

// CreateInterceptor creates a ConnectRPC unary interceptor that automatically
// checks policies for each incoming request.
//
// The policyMap should map procedure paths to policy structs, typically
// the generated PolicyMap from protoc-gen-policy-map.
//
// Example:
//
//	checker := policycheck.New()
//	checker.Register("Permission", permissionHandler)
//	checker.Register("RateLimit", rateLimitHandler)
//
//	interceptor := checker.CreateInterceptor(userv1.PolicyMap)
//
//	path, handler := userconnect.NewUserServiceHandler(
//	    userHandler,
//	    connect.WithInterceptors(interceptor),
//	)
func (c *Checker) CreateInterceptor(policyMap any) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure

			// Look up policies for this procedure
			policies := c.lookupPolicies(policyMap, procedure)
			if policies == nil {
				// No policies for this endpoint, proceed
				return next(ctx, req)
			}

			// Check all policies
			if err := c.Check(ctx, policies, req); err != nil {
				return nil, err
			}

			// All checks passed, proceed to handler
			return next(ctx, req)
		}
	}
}

// lookupPolicies looks up policies from the policy map.
// The policyMap should be a map[string]PolicyProvider.
func (c *Checker) lookupPolicies(policyMap any, procedure string) any {
	if policyMap == nil {
		return nil
	}

	// Type assert to the expected map type
	// The generated PolicyMap is map[string]PolicyProvider
	providerMap, ok := policyMap.(map[string]PolicyProvider)
	if !ok {
		return nil
	}

	// Look up the procedure in the map
	provider, exists := providerMap[procedure]
	if !exists {
		return nil
	}

	return provider
}
