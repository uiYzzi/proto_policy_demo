package main

import (
	"fmt"
	"maps"
	"path"
	"sort"
	"strings"

	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// packageInfo holds all policy information for a single Go package.
type packageInfo struct {
	// The first file we encounter for this package.
	// Used for naming the output file and package statement.
	File *protogen.File
	// Merged policies from all files in this package.
	Policies map[string]*MethodPolicies
}

func main() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		packages := make(map[string]*packageInfo) // Key: GoImportPath

		// Phase 1: Collect and group policies by package from all files.
		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}

			// Extract policies from the current file.
			policies := extractPolicies(f, gen)
			if len(policies) == 0 {
				continue
			}

			// Get or create the package info struct for this file's package.
			importPath := string(f.GoImportPath)
			pkgInfo, ok := packages[importPath]
			if !ok {
				pkgInfo = &packageInfo{
					File:     f,
					Policies: make(map[string]*MethodPolicies),
				}
				packages[importPath] = pkgInfo
			}

			// Merge the policies from this file into the package's policies.
			maps.Copy(pkgInfo.Policies, policies)
		}

		// Phase 2: Generate one consolidated policy file per package.
		for _, pkgInfo := range packages {
			if len(pkgInfo.Policies) > 0 {
				generatePolicyMapFile(gen, pkgInfo.File, pkgInfo.Policies)
			}
		}

		return nil
	})
}

// PolicyRule represents a single parsed policy rule
type PolicyRule struct {
	TypeName string         // e.g., "Permission", "RateLimit"
	TypeURL  string         // e.g., "service.policy.Permission"
	Fields   map[string]any // Parsed field values
}

// MethodPolicies holds all policies for a method
type MethodPolicies struct {
	Rules []*PolicyRule
}

// extractPolicies extracts and parses policy annotations from all RPC methods
func extractPolicies(f *protogen.File, gen *protogen.Plugin) map[string]*MethodPolicies {
	policies := make(map[string]*MethodPolicies)

	// Get the file descriptor proto
	fdp := f.Proto

	// Iterate through services
	for svcIdx, service := range f.Services {
		svcProto := fdp.Service[svcIdx]

		// Iterate through methods
		for methodIdx, method := range service.Methods {
			methodProto := svcProto.Method[methodIdx]

			// Get method options
			if methodProto.Options != nil {
				opts := methodProto.Options
				msg := opts.ProtoReflect()

				// Try to find extension 50001 (method_options.policy)
				var methodPolicies *MethodPolicies
				msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
					if fd.IsExtension() && fd.Number() == 50001 {
						methodPolicies = parsePolicyRules(v.Message(), gen)
					}
					return true
				})

				if methodPolicies != nil && len(methodPolicies.Rules) > 0 {
					procedure := fmt.Sprintf("/%s.%s/%s",
						f.Desc.Package(),
						service.Desc.Name(),
						method.Desc.Name())
					policies[procedure] = methodPolicies
				}
			}
		}
	}

	return policies
}

// parsePolicyRules parses all rules from MethodPolicy message using dynamic reflection
func parsePolicyRules(msg protoreflect.Message, gen *protogen.Plugin) *MethodPolicies {
	result := &MethodPolicies{
		Rules: []*PolicyRule{},
	}

	// Get the 'rules' field (field number 1)
	rulesField := msg.Descriptor().Fields().ByNumber(1)
	if rulesField == nil {
		return result
	}

	rulesList := msg.Get(rulesField).List()

	// Process each rule (google.protobuf.Any)
	for i := 0; i < rulesList.Len(); i++ {
		anyMsg := rulesList.Get(i).Message()

		// Convert to anypb.Any
		anyProto := &anypb.Any{}
		anyBytes, err := proto.Marshal(anyMsg.Interface())
		if err != nil {
			continue
		}
		if err := proto.Unmarshal(anyBytes, anyProto); err != nil {
			continue
		}

		// Dynamically parse the policy message
		rule := parsePolicyMessage(anyProto, gen)
		if rule != nil {
			result.Rules = append(result.Rules, rule)
		}
	}

	return result
}

// parsePolicyMessage dynamically parses a policy message from Any
func parsePolicyMessage(anyProto *anypb.Any, gen *protogen.Plugin) *PolicyRule {
	// Find the message descriptor for this type
	var msgDesc protoreflect.MessageDescriptor

	// Search through all files to find the message descriptor
	for _, f := range gen.Files {
		msgDesc = findMessageByTypeURL(f.Desc, anyProto.TypeUrl)
		if msgDesc != nil {
			break
		}
	}

	if msgDesc == nil {
		return nil
	}

	// Create a dynamic message using dynamicpb
	msg := dynamicpb.NewMessage(msgDesc)
	if err := proto.Unmarshal(anyProto.Value, msg); err != nil {
		return nil
	}

	// Extract type name from type URL
	// e.g., "type.googleapis.com/service.policy.Permission" -> "Permission"
	typeParts := strings.Split(anyProto.TypeUrl, "/")
	fullType := typeParts[len(typeParts)-1]
	typeParts = strings.Split(fullType, ".")
	typeName := typeParts[len(typeParts)-1]

	rule := &PolicyRule{
		TypeName: typeName,
		TypeURL:  fullType,
		Fields:   make(map[string]any),
	}

	// Extract all fields using reflection
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		fieldName := string(fd.Name())
		rule.Fields[fieldName] = extractFieldValue(fd, v)
		return true
	})

	return rule
}

// findMessageByTypeURL finds a message descriptor by type URL
func findMessageByTypeURL(fileDesc protoreflect.FileDescriptor, typeURL string) protoreflect.MessageDescriptor {
	// Extract the full type name from URL
	parts := strings.Split(typeURL, "/")
	fullTypeName := parts[len(parts)-1]

	return findMessageByName(fileDesc, protoreflect.FullName(fullTypeName))
}

// findMessageByName recursively finds a message descriptor by full name
func findMessageByName(fileDesc protoreflect.FileDescriptor, name protoreflect.FullName) protoreflect.MessageDescriptor {
	messages := fileDesc.Messages()
	for i := 0; i < messages.Len(); i++ {
		msg := messages.Get(i)
		if msg.FullName() == name {
			return msg
		}
		// Search nested messages
		if nested := findNestedMessage(msg, name); nested != nil {
			return nested
		}
	}
	return nil
}

// findNestedMessage recursively searches nested messages
func findNestedMessage(msg protoreflect.MessageDescriptor, name protoreflect.FullName) protoreflect.MessageDescriptor {
	nested := msg.Messages()
	for i := 0; i < nested.Len(); i++ {
		m := nested.Get(i)
		if m.FullName() == name {
			return m
		}
		if result := findNestedMessage(m, name); result != nil {
			return result
		}
	}
	return nil
}

// extractFieldValue extracts a field value and converts it to Go type
func extractFieldValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return v.Bool()
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return int32(v.Int())
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return v.Int()
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return uint32(v.Uint())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return v.Uint()
	case protoreflect.FloatKind:
		return float32(v.Float())
	case protoreflect.DoubleKind:
		return v.Float()
	case protoreflect.StringKind:
		return v.String()
	case protoreflect.BytesKind:
		return v.Bytes()
	default:
		return nil
	}
}

// generatePolicyMapFile generates a .policy.pb.go file with dynamically generated types
func generatePolicyMapFile(gen *protogen.Plugin, f *protogen.File, policies map[string]*MethodPolicies) {
	// Create a single filename per package, e.g., "service.policy.pb.go"
	packageDir := path.Dir(f.GeneratedFilenamePrefix)
	packageName := string(f.GoPackageName)
	filename := path.Join(packageDir, packageName+".policy.pb.go")
	g := gen.NewGeneratedFile(filename, f.GoImportPath)

	// Write file header
	g.P("// Code generated by protoc-gen-policy-map. DO NOT EDIT.")
	g.P()
	g.P("package ", f.GoPackageName)
	g.P()

	// Collect all unique policy types
	typeFields := make(map[string]map[string]string) // TypeName -> FieldName -> FieldType

	for _, methodPolicies := range policies {
		for _, rule := range methodPolicies.Rules {
			if _, exists := typeFields[rule.TypeName]; !exists {
				typeFields[rule.TypeName] = make(map[string]string)
			}
			for fieldName, fieldValue := range rule.Fields {
				typeFields[rule.TypeName][fieldName] = inferGoType(fieldValue)
			}
		}
	}

	// For deterministic output, sort the type names
	var sortedTypeNames []string
	for typeName := range typeFields {
		sortedTypeNames = append(sortedTypeNames, typeName)
	}
	sort.Strings(sortedTypeNames)

	// Generate type definitions
	for _, typeName := range sortedTypeNames {
		fields := typeFields[typeName]
		g.P("// ", typeName, " represents the ", typeName, " policy")
		g.P("type ", typeName, " struct {")

		// Sort fields for deterministic output
		var sortedFieldNames []string
		for fieldName := range fields {
			sortedFieldNames = append(sortedFieldNames, fieldName)
		}
		sort.Strings(sortedFieldNames)

		for _, fieldName := range sortedFieldNames {
			fieldType := fields[fieldName]
			goFieldName := snakeToPascal(fieldName)
			g.P("\t", goFieldName, " ", fieldType)
		}
		g.P("}")
		g.P()
	}

	// Generate MethodPolicies struct
	g.P("// MethodPolicies contains all policies for a method")
	g.P("type MethodPolicies struct {")
	// Use the sorted list of type names for deterministic field order
	for _, typeName := range sortedTypeNames {
		g.P("\t", typeName, " *", typeName)
	}
	g.P("}")
	g.P()

	// Generate GetPolicies method to implement PolicyProvider interface
	g.P("// GetPolicies returns all non-nil policies in this MethodPolicies instance.")
	g.P("// This method allows MethodPolicies to implement the PolicyProvider interface.")
	g.P("func (m *MethodPolicies) GetPolicies() []any {")
	g.P("\tif m == nil {")
	g.P("\t\treturn nil")
	g.P("\t}")
	g.P("\tvar list []any")
	// Use the sorted list for deterministic checks
	for _, typeName := range sortedTypeNames {
		g.P("\tif m.", typeName, " != nil {")
		g.P("\t\tlist = append(list, m.", typeName, ")")
		g.P("\t}")
	}
	g.P("\treturn list")
	g.P("}")
	g.P()

	// Write the policy map with PolicyProvider interface type
	g.P("// PolicyMap maps ConnectRPC procedure paths to their policies")
	g.P("// All policies are parsed at compile time for type safety and performance")
	g.P("var PolicyMap = map[string]*MethodPolicies{")

	// Sort procedures for deterministic map output
	var sortedProcedures []string
	for procedure := range policies {
		sortedProcedures = append(sortedProcedures, procedure)
	}
	sort.Strings(sortedProcedures)

	for _, procedure := range sortedProcedures {
		methodPolicies := policies[procedure]
		g.P("\t", fmt.Sprintf("%q: {", procedure))

		// Sort rules within a method for deterministic output
		sort.Slice(methodPolicies.Rules, func(i, j int) bool {
			return methodPolicies.Rules[i].TypeName < methodPolicies.Rules[j].TypeName
		})

		for _, rule := range methodPolicies.Rules {
			g.P("\t\t", rule.TypeName, ": &", rule.TypeName, "{")

			// Sort fields within a rule for deterministic output
			var sortedFieldNames []string
			for fieldName := range rule.Fields {
				sortedFieldNames = append(sortedFieldNames, fieldName)
			}
			sort.Strings(sortedFieldNames)

			for _, fieldName := range sortedFieldNames {
				fieldValue := rule.Fields[fieldName]
				goFieldName := snakeToPascal(fieldName)
				g.P("\t\t\t", goFieldName, ": ", formatGoValue(fieldValue), ",")
			}
			g.P("\t\t},")
		}

		g.P("\t},")
	}
	g.P("}")
}

// inferGoType infers the Go type from a value
func inferGoType(value any) string {
	switch value.(type) {
	case bool:
		return "bool"
	case int32:
		return "int32"
	case int64:
		return "int64"
	case uint32:
		return "uint32"
	case uint64:
		return "uint64"
	case float32:
		return "float32"
	case float64:
		return "float64"
	case string:
		return "string"
	case []byte:
		return "[]byte"
	default:
		return "any"
	}
}

// formatGoValue formats a value for Go code
func formatGoValue(value any) string {
	switch v := value.(type) {
	case bool:
		return fmt.Sprintf("%t", v)
	case int32, int64, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%f", v)
	case string:
		return fmt.Sprintf("%q", v)
	case []byte:
		return fmt.Sprintf("[]byte{%s}", bytesToGoArray(v))
	default:
		return "nil"
	}
}

// bytesToGoArray converts []byte to Go array literal
func bytesToGoArray(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var builder strings.Builder
	for i, b := range data {
		if i > 0 {
			builder.WriteString(", ")
		}
		fmt.Fprintf(&builder, "0x%02x", b)
	}
	return builder.String()
}

// snakeToPascal converts snake_case to PascalCase
func snakeToPascal(s string) string {
	parts := strings.Split(s, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}
