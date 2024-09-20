/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cel

import (
	"fmt"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"

	"k8s.io/apimachinery/pkg/util/version"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

const (
	subjectAccessReviewRequestVarName = "request"

	fieldSelectorVarName = "fieldSelector"
	labelSelectorVarName = "labelSelector"
)

// CompilationResult represents a compiled authorization cel expression.
type CompilationResult struct {
	Program    cel.Program
	Expression string

	// These track if a given expression uses fieldSelector and labelSelector,
	// so construction of data passed to the CEL expression can be optimized if those fields are unused.
	UsesFieldSelector bool
	UsesLabelSelector bool
}

// Compiler is an interface for compiling CEL expressions with the desired environment mode.
type Compiler interface {
	CompileCELExpression(expression string) (CompilationResult, error)
}

type compiler struct {
	envSet *environment.EnvSet
}

// NewCompiler returns a new Compiler.
func NewCompiler(env *environment.EnvSet) Compiler {
	return &compiler{
		envSet: mustBuildEnv(env),
	}
}

func (c compiler) CompileCELExpression(expression string) (CompilationResult, error) {
	resultError := func(errorString string, errType apiservercel.ErrorType) (CompilationResult, error) {
		err := &apiservercel.Error{
			Type:   errType,
			Detail: errorString,
		}
		return CompilationResult{
			Expression: expression,
		}, err
	}
	env, err := c.envSet.Env(environment.StoredExpressions)
	if err != nil {
		return resultError(fmt.Sprintf("unexpected error loading CEL environment: %v", err), apiservercel.ErrorTypeInternal)
	}
	ast, issues := env.Compile(expression)
	if issues != nil {
		return resultError("compilation failed: "+issues.String(), apiservercel.ErrorTypeInvalid)
	}
	if ast.OutputType() != cel.BoolType {
		return resultError(fmt.Sprintf("expression must evaluate to bool but got %v", ast.OutputType()), apiservercel.ErrorTypeInvalid)
	}

	checkedExpr, err := cel.AstToCheckedExpr(ast)
	if err != nil {
		// should be impossible since env.Compile returned no issues
		return resultError("unexpected compilation error: "+err.Error(), apiservercel.ErrorTypeInternal)
	}
	celAST, err := celast.ToAST(checkedExpr)
	if err != nil {
		// should be impossible since env.Compile returned no issues
		return resultError("unexpected compilation error: "+err.Error(), apiservercel.ErrorTypeInternal)
	}

	var usesFieldSelector, usesLabelSelector bool
	celast.PreOrderVisit(celast.NavigateAST(celAST), celast.NewExprVisitor(func(e celast.Expr) {
		// we already know we use both, no need to inspect more
		if usesFieldSelector && usesLabelSelector {
			return
		}

		var fieldName string
		switch e.Kind() {
		case celast.SelectKind:
			// simple select (.fieldSelector / .labelSelector)
			fieldName = e.AsSelect().FieldName()
		case celast.CallKind:
			// optional select (.?fieldSelector / .?labelSelector)
			if e.AsCall().FunctionName() != operators.OptSelect {
				return
			}
			args := e.AsCall().Args()
			// args[0] is the receiver (what comes before the `.?`), args[1] is the field name being optionally selected (what comes after the `.?`)
			if len(args) != 2 || args[1].Kind() != celast.LiteralKind || args[1].AsLiteral().Type() != cel.StringType {
				return
			}
			fieldName, _ = args[1].AsLiteral().Value().(string)
		}

		switch fieldName {
		case fieldSelectorVarName:
			usesFieldSelector = true
		case labelSelectorVarName:
			usesLabelSelector = true
		}
	}))

	prog, err := env.Program(ast)
	if err != nil {
		return resultError("program instantiation failed: "+err.Error(), apiservercel.ErrorTypeInternal)
	}
	return CompilationResult{
		Program:           prog,
		Expression:        expression,
		UsesFieldSelector: usesFieldSelector,
		UsesLabelSelector: usesLabelSelector,
	}, nil
}

func mustBuildEnv(baseEnv *environment.EnvSet) *environment.EnvSet {
	field := func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField {
		return apiservercel.NewDeclField(name, declType, required, nil, nil)
	}
	fields := func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField {
		result := make(map[string]*apiservercel.DeclField, len(fields))
		for _, f := range fields {
			result[f.Name] = f
		}
		return result
	}
	subjectAccessReviewSpecRequestType := buildRequestType(field, fields)
	extended, err := baseEnv.Extend(
		environment.VersionedOptions{
			// we record this as 1.0 since it was available in the
			// first version that supported this feature
			IntroducedVersion: version.MajorMinor(1, 0),
			EnvOptions: []cel.EnvOption{
				cel.Variable(subjectAccessReviewRequestVarName, subjectAccessReviewSpecRequestType.CelType()),
			},
			DeclTypes: []*apiservercel.DeclType{
				subjectAccessReviewSpecRequestType,
			},
		},
	)
	if err != nil {
		panic(fmt.Sprintf("environment misconfigured: %v", err))
	}

	return extended
}

// buildRequestType generates a DeclType for SubjectAccessReviewSpec.
// if attributes are added here, also add to convertObjectToUnstructured.
func buildRequestType(field func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField, fields func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField) *apiservercel.DeclType {
	resourceAttributesType := buildResourceAttributesType(field, fields)
	return apiservercel.NewObjectType("kubernetes.SubjectAccessReviewSpec", fields(
		field("resourceAttributes", resourceAttributesType, false),
		field("user", apiservercel.StringType, false),
		field("uid", apiservercel.StringType, false),
		field("groups", apiservercel.NewListType(apiservercel.StringType, -1), false),
		field("extra", apiservercel.NewMapType(apiservercel.StringType, apiservercel.NewListType(apiservercel.StringType, -1), -1), false),
	))
}

// buildResourceAttributesType generates a DeclType for ResourceAttributes.
// if attributes are added here, also add to convertObjectToUnstructured.
func buildResourceAttributesType(field func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField, fields func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField) *apiservercel.DeclType {
	resourceAttributesFields := []*apiservercel.DeclField{
		field("namespace", apiservercel.StringType, false),
		field("name", apiservercel.StringType, false),
		field("fieldSelector", buildFieldSelectorType(field, fields), false),
		field("labelSelector", buildLabelSelectorType(field, fields), false),
	}

	return apiservercel.NewObjectType("kubernetes.ResourceAttributes", fields(resourceAttributesFields...))
}

func buildFieldSelectorType(field func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField, fields func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField) *apiservercel.DeclType {
	return apiservercel.NewObjectType("kubernetes.FieldSelectorAttributes", fields(
		field("requirements", apiservercel.NewListType(buildSelectorRequirementType(field, fields), -1), false),
	))
}

func buildLabelSelectorType(field func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField, fields func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField) *apiservercel.DeclType {
	return apiservercel.NewObjectType("kubernetes.LabelSelectorAttributes", fields(
		field("requirements", apiservercel.NewListType(buildSelectorRequirementType(field, fields), -1), false),
	))
}

func buildSelectorRequirementType(field func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField, fields func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField) *apiservercel.DeclType {
	return apiservercel.NewObjectType("kubernetes.SelectorRequirement", fields(
		field("key", apiservercel.StringType, false),
		field("operator", apiservercel.StringType, false),
		field("values", apiservercel.NewListType(apiservercel.StringType, -1), false),
	))
}

func convertObjectToUnstructured(conditionalAttributes ConditionalAttributes, includeFieldSelector, includeLabelSelector bool) map[string]interface{} {
	extra := conditionalAttributes.GetUser().GetExtra()
	if extra == nil {
		extra = map[string][]string{}
	}
	ret := map[string]interface{}{
		"user":   conditionalAttributes.GetUser().GetName(),
		"uid":    conditionalAttributes.GetUser().GetUID(),
		"groups": conditionalAttributes.GetUser().GetGroups(),
		"extra":  extra,
	}
	resourceAttributes := map[string]interface{}{
		"namespace": conditionalAttributes.GetNamespace(),
		"name":      conditionalAttributes.GetName(),
	}

	if includeFieldSelector {
		fieldSelector, err := conditionalAttributes.GetFieldSelector()
		if err != nil {
			fieldSelector = nil
		}

		if len(fieldSelector) > 0 {
			requirements := make([]map[string]interface{}, 0, len(fieldSelector))
			for _, r := range fieldSelector {
				requirements = append(requirements, map[string]interface{}{
					"key":      r.Field,
					"operator": r.Operator,
					"values":   []string{r.Value},
				})
			}
			resourceAttributes[fieldSelectorVarName] = map[string]interface{}{"requirements": requirements}
		}
	}

	if includeLabelSelector {
		labelSelector, err := conditionalAttributes.GetLabelSelector()
		if err != nil {
			labelSelector = nil
		}

		if len(labelSelector) > 0 {
			requirements := make([]map[string]interface{}, 0, len(labelSelector))
			for _, r := range labelSelector {
				requirements = append(requirements, map[string]interface{}{
					"key":      r.Key(),
					"operator": r.Operator(),
					"values":   r.ValuesUnsorted(),
				})
			}
			resourceAttributes[labelSelectorVarName] = map[string]interface{}{"requirements": requirements}
		}
	}

	ret["resourceAttributes"] = resourceAttributes

	return ret
}
