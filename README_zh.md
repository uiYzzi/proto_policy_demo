# Protobuf 驱动的策略执行框架演示

本项目演示了一个声明式的、由 Protobuf 驱动的策略执行框架。它用于在基于 Go 和 [ConnectRPC](https://connectrpc.com/) 的服务中实施策略（如权限和速率限制）。

[English Readme](./README.md)

## 项目简介

核心思想是直接在 `.proto` 文件中，通过方法选项 (method options) 来定义策略。然后，一个自定义的 `protoc` 插件会生成一个静态的策略映射表，运行时的拦截器 (interceptor) 使用这个映射表来强制执行这些策略。这种方法将策略定义与 API 定义放在一起，提供了统一的可信来源。

### 关键组件

*   **`proto/`**: 包含了 `UserService` 服务的 Protobuf 定义。
    *   `method_options/options.proto` 中的自定义选项用于声明策略。
    *   `CreateUser` 和 `GetUser` 等 RPC 方法都附加了 `Permission` (权限) 和 `RateLimit` (速率限制) 策略。
*   **`tools/protoc-gen-policy-map`**: 一个 `protoc` 插件，它会读取 `.proto` 文件中的自定义策略选项，并生成一个包含 `PolicyMap` 的 Go 源文件。这个 map 将每个 RPC 过程路径链接到其对应的策略。
*   **`pkg/policycheck/`**: 一个通用的运行时库，提供 ConnectRPC 的 `UnaryInterceptor`。此拦截器在生成的 `PolicyMap` 中查找传入请求的策略，并为每个策略执行相应的处理器。
*   **`cmd/server/`**: 一个简单的服务器，演示了如何将所有部分组合在一起：它向检查器注册策略处理器，并将策略检查拦截器附加到服务上。

## 工作原理

1.  **定义 (Define)**: 在 `.proto` 文件中，使用自定义选项在 RPC 方法上定义策略。
    ```protobuf
    //位于 proto/service/user/user.proto
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
2.  **生成 (Generate)**: 运行 `buf generate` 会调用 `protoc-gen-policy-map` 插件，该插件会创建一个从 RPC 过程到其策略的 Go 映射表。
3.  **注册 (Register)**: 在服务器的启动代码中，创建一个 `policycheck.Checker` 并为你的策略类型注册处理器（例如，一个检查用户身份声明的 `Permission` 处理器，一个与令牌桶集成的 `RateLimit` 处理器）。
    ```go
    // 示例来自 cmd/server/main.go
    checker := policycheck.New()
    checker.Register("Permission", permissionHandler)
    checker.Register("RateLimit", rateLimitHandler)
    ```
4.  **拦截 (Intercept)**: 检查器的拦截器被添加到 ConnectRPC 服务处理器中。对于每个传入的请求，它会在执行实际业务逻辑之前，自动查找并运行所需的策略检查。
    ```go
    interceptor := checker.CreateInterceptor(userv1.PolicyMap)
    svc := connect.WithInterceptors(interceptor)
    ```

## 如何使用

要运行此项目，首先需要从 Protobuf 定义生成代码：

1.  **安装工具**: 确保已安装 `protoc`, `buf`, 以及所有必需的 Go 插件。
2.  **生成代码**:
    ```shell
    buf generate
    ```
3.  **运行服务器**:
    ```shell
    go run ./cmd/server/main.go
    ```
