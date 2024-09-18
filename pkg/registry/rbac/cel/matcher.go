/*
Copyright 2023 The Kubernetes Authors.

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
	"context"
	"fmt"

	celgo "github.com/google/cel-go/cel"
)

type CELMatcher struct {
	CompilationResults []CompilationResult

	// These track if any expressions use fieldSelector and labelSelector,
	// so construction of data passed to the CEL expression can be optimized if those fields are unused.
	UsesLabelSelector bool
	UsesFieldSelector bool
}

func (c *CELMatcher) Eval(ctx context.Context, conditionalAttributes ConditionalAttributes) (bool, error) {
	va := map[string]interface{}{
		"request": convertObjectToUnstructured(conditionalAttributes, c.UsesFieldSelector, c.UsesLabelSelector),
	}
	for _, compilationResult := range c.CompilationResults {
		evalResult, _, err := compilationResult.Program.ContextEval(ctx, va)
		if err != nil {
			return false, fmt.Errorf("cel evaluation error: expression '%v' resulted in error: %w", compilationResult.Expression, err)
		}
		if evalResult.Type() != celgo.BoolType {
			return false, fmt.Errorf("cel evaluation error: expression '%v' eval result type should be bool but got %W", compilationResult.Expression, evalResult.Type())
		}
		match, ok := evalResult.Value().(bool)
		if !ok {
			return false, fmt.Errorf("cel evaluation error: expression '%v' eval result value should be bool but got %W", compilationResult.Expression, evalResult.Value())
		}
		// If at least one matchCondition successfully evaluates to FALSE,
		// return early
		if !match {
			return false, nil
		}
	}

	// return ALL matchConditions evaluate to TRUE successfully without error
	return true, nil
}
