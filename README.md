# Protobuf-Driven Policy Enforcement Demo

This project demonstrates a declarative, Protobuf-driven framework for enforcing policies (like permissions and rate limiting) in a Go-based [ConnectRPC](https://connectrpc.com/) service.

[中文文档](./README_zh.md)

## Overview

The core idea is to define policies directly within your `.proto` files as method options. A custom `protoc` plugin then generates a static map of these policies, which a runtime interceptor uses to enforce them. This approach keeps your policy definitions alongside your API definitions, providing a single source of truth.

### Key Components

*   **`proto/`**: Contains the Protobuf definitions for a simple `UserService`.
    *   Custom options in `method_options/options.proto` are used to declare policies.
    *   RPC methods like `CreateUser` and `GetUser` have `Permission` and `RateLimit` policies attached to them.
*   **`tools/protoc-gen-policy-map`**: A `protoc` plugin that reads the custom policy options from `.proto` files and generates a Go source file containing a `PolicyMap`. This map links each RPC procedure path to its corresponding policies.
*   **`pkg/policycheck/`**: A generic runtime library that provides a ConnectRPC `UnaryInterceptor`. This interceptor looks up policies for the incoming request in the generated `PolicyMap` and executes the appropriate handler for each policy.
*   **`cmd/server/`**: A simple server that demonstrates how to tie everything together: it registers policy handlers with the checker and attaches the policy-checking interceptor to the service.

## How It Works

1.  **Define**: Policies are defined on RPC methods in `.proto` files using custom options.
    ```protobuf
    // In proto/service/user/user.proto
    rpc CreateUser(CreateUserRequest) returns (CreateUserResponse) {
      option (method_options.policy) = {
        rules: [
          {
            [type.googleapis.com/service.policy.Permission]: { required: "user:write" }
          },
          {
            [type.googleapis.com/service.policy.RateLimit]: { qps: 100 }
          }
        ]
      };
    }
    ```
2.  **Generate**: Running `buf generate` invokes the `protoc-gen-policy-map` plugin, which creates a Go map of procedures to their policies.
3.  **Register**: In your server's startup code, you create a `policycheck.Checker` and register handlers for your policy types (e.g., a `Permission` handler that checks a user's claims, a `RateLimit` handler that integrates with a token bucket).
    ```go
    // Example from cmd/server/main.go
    checker := policycheck.New()
    checker.Register("Permission", permissionHandler)
    checker.Register("RateLimit", rateLimitHandler)
    ```
4.  **Intercept**: The checker's interceptor is added to the ConnectRPC service handler. For each incoming request, it automatically finds and runs the required policy checks before executing the actual business logic.
    ```go
    interceptor := checker.CreateInterceptor(userv1.PolicyMap)
    svc := connect.WithInterceptors(interceptor)
    ```

## Usage

To run the project, you first need to generate the code from the Protobuf definitions:

1.  **Install tools**: Make sure you have `protoc`, `buf`, and the necessary Go plugins installed.
2.  **Generate code**:
    ```shell
    buf generate
    ```
3.  **Run the server**:
    ```shell
    go run ./cmd/server/main.go
    ```
