// Package policycheck provides a generic policy checking framework for ConnectRPC services.
// It allows services to register custom policy handlers and automatically execute them
// based on generated policy maps.
package policycheck

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
)

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
// It calls the provider's GetPolicies() method to retrieve all policies
// and then invokes the corresponding handler for each policy based on its type.
//
// The provider parameter must implement GetPolicies() []any.
func Check[M interface{ GetPolicies() []any }](handlers map[string]Handler, ctx context.Context, provider M, req connect.AnyRequest) error {
	policyList := provider.GetPolicies()

	// Iterate through each policy
	for _, policy := range policyList {
		if policy == nil {
			continue
		}

		// Get the type name
		typeName := getPolicyTypeName(policy)
		if typeName == "" {
			continue
		}

		// Look up the handler
		handler, exists := handlers[typeName]
		if !exists {
			continue
		}

		// Execute the handler
		if err := handler(ctx, policy, req); err != nil {
			return fmt.Errorf("policy check failed for %s: %w", typeName, err)
		}
	}

	return nil
}

func getPolicyTypeName(policy any) string {
	typeName := fmt.Sprintf("%T", policy)
	if len(typeName) > 0 && typeName[0] == '*' {
		typeName = typeName[1:]
	}
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
//	interceptor := policycheck.CreateInterceptor(checker, userv1.PolicyMap)
//
//	path, handler := userconnect.NewUserServiceHandler(
//	    userHandler,
//	    connect.WithInterceptors(interceptor),
//	)
//
// Note: This function uses generics with interface constraint to ensure type safety.
// The generic parameter M must implement GetPolicies() []any, which is satisfied by
// generated MethodPolicies struct pointers.
func CreateInterceptor[M interface{ GetPolicies() []any }](c *Checker, policyMap map[string]M) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure

			// Look up policies for this procedure
			provider, exists := policyMap[procedure]
			if !exists {
				return next(ctx, req)
			}

			// Check all policies
			if err := Check(c.handlers, ctx, provider, req); err != nil {
				return nil, err
			}

			// All checks passed, proceed to handler
			return next(ctx, req)
		}
	}
}
