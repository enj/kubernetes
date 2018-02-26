/*
Copyright 2014 The Kubernetes Authors.

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

package runtime

import (
	"fmt"
	"sync"
	"testing"

	"github.com/golang/groupcache/lru"
)

func TestHandleCrash(t *testing.T) {
	defer func() {
		if x := recover(); x == nil {
			t.Errorf("Expected a panic to recover from")
		}
	}()
	defer HandleCrash()
	panic("Test Panic")
}

func TestCustomHandleCrash(t *testing.T) {
	old := PanicHandlers
	defer func() { PanicHandlers = old }()
	var result interface{}
	PanicHandlers = []func(interface{}){
		func(r interface{}) {
			result = r
		},
	}
	func() {
		defer func() {
			if x := recover(); x == nil {
				t.Errorf("Expected a panic to recover from")
			}
		}()
		defer HandleCrash()
		panic("test")
	}()
	if result != "test" {
		t.Errorf("did not receive custom handler")
	}
}

func TestCustomHandleError(t *testing.T) {
	old := ErrorHandlers
	defer func() { ErrorHandlers = old }()
	var result error
	ErrorHandlers = []func(error){
		func(err error) {
			result = err
		},
	}
	err := fmt.Errorf("test")
	HandleError(err)
	if result != err {
		t.Errorf("did not receive custom handler")
	}
}

func TestGlobalDedupingErrorHandlerChangeSimilar(t *testing.T) {
	oldCount := DedupingErrorHandler.count
	oldCache := DedupingErrorHandler.cache
	oldSimilar := DedupingErrorHandler.Similar
	defer func() {
		DedupingErrorHandler.count = oldCount
		DedupingErrorHandler.cache = oldCache
		DedupingErrorHandler.Similar = oldSimilar
	}()

	// temporarily reset any global state
	resetGlobalDedupingErrorHandler()

	errs := []error{
		fmt.Errorf("test1"),
		fmt.Errorf("test2"),
		fmt.Errorf("test3"),
	}

	// with the default similar of 1, these are all considered different errors
	// we must do this in a for loop otherwise the errors will have a different stack
	for _, err := range errs {
		HandleError(err)
	}

	checkCount(t, DedupingErrorHandler.count, 3, 1)

	// reset again so we can see the effects of changing similar
	resetGlobalDedupingErrorHandler()

	// enable fuzzy matching
	DedupingErrorHandler.Similar = 0.75

	// now these should all be considered the same error
	for _, err := range errs {
		HandleError(err)
	}

	checkCount(t, DedupingErrorHandler.count, 1, 3)
}

func TestGlobalDedupingErrorHandlerGoroutineSafe(t *testing.T) {
	oldCount := DedupingErrorHandler.count
	oldCache := DedupingErrorHandler.cache
	oldSimilar := DedupingErrorHandler.Similar
	defer func() {
		DedupingErrorHandler.count = oldCount
		DedupingErrorHandler.cache = oldCache
		DedupingErrorHandler.Similar = oldSimilar
	}()

	// temporarily reset any global state
	resetGlobalDedupingErrorHandler()

	// use untyped ints to make comparisons easier
	const (
		uniqueErrs   = 50
		errFrequency = 70
	)

	wg := sync.WaitGroup{}
	for i := 0; i < errFrequency; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < uniqueErrs; j++ {
				HandleError(fmt.Errorf("testwithenoughsamedata%d", j))
			}
			wg.Done()
		}()
	}
	wg.Wait()

	checkCount(t, DedupingErrorHandler.count, uniqueErrs, errFrequency)

	// reset again so we can see the effects of changing similar
	resetGlobalDedupingErrorHandler()

	// enable fuzzy matching
	DedupingErrorHandler.Similar = 0.75

	// now these should all be considered the same error
	wg2 := sync.WaitGroup{}
	for i := 0; i < errFrequency; i++ {
		wg2.Add(1)
		go func() {
			for j := 0; j < uniqueErrs; j++ {
				HandleError(fmt.Errorf("testwithenoughsamedata%d", j))
			}
			wg2.Done()
		}()
	}
	wg2.Wait()

	checkCount(t, DedupingErrorHandler.count, 1, uniqueErrs*errFrequency)
}

func checkCount(t *testing.T, count map[errKey]errVal, unique int, frequency uint64) {
	t.Helper()

	if length := len(count); length != unique {
		t.Errorf("expected length %d got %d", unique, length)
	}

	for key, val := range count {
		if val.count != frequency {
			t.Errorf("expected count of %d for key=%v val=%v", frequency, key, val)
		}
	}
}

func resetGlobalDedupingErrorHandler() {
	DedupingErrorHandler.count = make(map[errKey]errVal)
	DedupingErrorHandler.cache = lru.New(cacheSize)
	DedupingErrorHandler.cache.OnEvicted = func(key lru.Key, _ interface{}) {
		delete(DedupingErrorHandler.count, key.(errKey))
	}
}
