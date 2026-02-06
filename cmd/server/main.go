package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/time/rate"

	servicev1 "proto_policy_demo/gen/service"
	"proto_policy_demo/gen/service/serviceconnect"
	"proto_policy_demo/pkg/policycheck"
)

// UserServiceHandler implements the UserService
type UserServiceHandler struct{}

// CreateUser implements the CreateUser RPC
func (s *UserServiceHandler) CreateUser(
	ctx context.Context,
	req *connect.Request[servicev1.CreateUserRequest],
) (*connect.Response[servicev1.CreateUserResponse], error) {
	log.Printf("CreateUser called: name=%s, email=%s", req.Msg.Name, req.Msg.Email)

	user := &servicev1.User{
		Id:    "user-123",
		Name:  req.Msg.Name,
		Email: req.Msg.Email,
	}

	return connect.NewResponse(&servicev1.CreateUserResponse{
		User: user,
	}), nil
}

// GetUser implements the GetUser RPC
func (s *UserServiceHandler) GetUser(
	ctx context.Context,
	req *connect.Request[servicev1.GetUserRequest],
) (*connect.Response[servicev1.GetUserResponse], error) {
	log.Printf("GetUser called: id=%s", req.Msg.Id)

	user := &servicev1.User{
		Id:    req.Msg.Id,
		Name:  "John Doe",
		Email: "john@example.com",
	}

	return connect.NewResponse(&servicev1.GetUserResponse{
		User: user,
	}), nil
}

// RateLimiterManager manages rate limiters per procedure
type RateLimiterManager struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewRateLimiterManager() *RateLimiterManager {
	return &RateLimiterManager{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (m *RateLimiterManager) GetLimiter(procedure string, qps, burst int32) *rate.Limiter {
	m.mu.RLock()
	limiter, exists := m.limiters[procedure]
	m.mu.RUnlock()

	if exists {
		return limiter
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if limiter, exists := m.limiters[procedure]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rate.Limit(qps), int(burst))
	m.limiters[procedure] = limiter
	return limiter
}

var rateLimiterManager = NewRateLimiterManager()

func main() {
	// Create policy checker
	checker := policycheck.New()

	// Register Permission policy handler
	checker.Register("Permission", func(ctx context.Context, policy any, req connect.AnyRequest) error {
		perm := policy.(*servicev1.Permission)

		log.Printf("Checking permission for %s: required=%s", req.Spec().Procedure, perm.Required)

		// Extract token from Authorization header
		token := req.Header().Get("Authorization")
		if token == "" {
			return connect.NewError(
				connect.CodeUnauthenticated,
				errors.New("missing authorization header"),
			)
		}

		token = strings.TrimPrefix(token, "Bearer ")

		// Simple permission check: token should contain the required permission
		// In production, you would decode JWT and check claims
		if !strings.Contains(token, perm.Required) {
			return connect.NewError(
				connect.CodePermissionDenied,
				fmt.Errorf("insufficient permissions: required=%s", perm.Required),
			)
		}

		log.Printf("Permission granted for %s", req.Spec().Procedure)
		return nil
	})

	// Register RateLimit policy handler
	checker.Register("RateLimit", func(ctx context.Context, policy any, req connect.AnyRequest) error {
		limit := policy.(*servicev1.RateLimit)

		log.Printf("Checking rate limit for %s: qps=%d, burst=%d",
			req.Spec().Procedure, limit.Qps, limit.Burst)

		limiter := rateLimiterManager.GetLimiter(req.Spec().Procedure, limit.Qps, limit.Burst)

		if !limiter.Allow() {
			return connect.NewError(
				connect.CodeResourceExhausted,
				fmt.Errorf("rate limit exceeded: max %d qps", limit.Qps),
			)
		}

		log.Printf("Rate limit passed for %s", req.Spec().Procedure)
		return nil
	})

	// Create the user service handler
	userHandler := &UserServiceHandler{}

	// Create HTTP mux
	mux := http.NewServeMux()

	// Register the UserService with policy checker interceptor
	path, handler := serviceconnect.NewUserServiceHandler(
		userHandler,
		connect.WithInterceptors(policycheck.CreateInterceptor(checker, servicev1.PolicyMap)),
	)
	mux.Handle(path, handler)

	// Add a simple health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Print usage information
	fmt.Println("========================================")
	fmt.Println("ConnectRPC Policy Demo Server")
	fmt.Println("========================================")
	fmt.Println("Server listening on http://localhost:8080")
	fmt.Println()
	fmt.Println("Policies loaded:")
	for procedure, methodPolicies := range servicev1.PolicyMap {
		fmt.Printf("  %s:\n", procedure)
		// Use the PolicyProvider interface to iterate through policies
		for _, policy := range methodPolicies.GetPolicies() {
			switch p := policy.(type) {
			case *servicev1.Permission:
				fmt.Printf("    - Permission: %s\n", p.Required)
			case *servicev1.RateLimit:
				fmt.Printf("    - Rate Limit: %d QPS (burst: %d)\n", p.Qps, p.Burst)
			}
		}
	}
	fmt.Println()
	fmt.Println("Example curl commands:")
	fmt.Println()
	fmt.Println("# CreateUser (will fail - no permission)")
	fmt.Println(`curl -X POST http://localhost:8080/service.user.UserService/CreateUser \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user:read" \
  -d '{"name":"Alice","email":"alice@example.com"}'`)
	fmt.Println()
	fmt.Println("# CreateUser (will succeed)")
	fmt.Println(`curl -X POST http://localhost:8080/service.user.UserService/CreateUser \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user:write" \
  -d '{"name":"Alice","email":"alice@example.com"}'`)
	fmt.Println()
	fmt.Println("# GetUser (will succeed)")
	fmt.Println(`curl -X POST http://localhost:8080/service.user.UserService/GetUser \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user:read" \
  -d '{"id":"user-123"}'`)
	fmt.Println()
	fmt.Println("========================================")

	// Start server with h2c support (HTTP/2 without TLS)
	if err := http.ListenAndServe(
		"localhost:8080",
		h2c.NewHandler(mux, &http2.Server{}),
	); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
