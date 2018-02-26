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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/golang/groupcache/lru"

	"k8s.io/apimachinery/pkg/util/clock"
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

	checkGlobalDedupingErrorHandlerCount(t, 3, 1)

	// reset again so we can see the effects of changing similar
	resetGlobalDedupingErrorHandler()

	// enable fuzzy matching
	DedupingErrorHandler.Similar = 0.75

	// now these should all be considered the same error
	for _, err := range errs {
		HandleError(err)
	}

	checkGlobalDedupingErrorHandlerCount(t, 1, 3)
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

	checkGlobalDedupingErrorHandlerCount(t, uniqueErrs, errFrequency)

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

	checkGlobalDedupingErrorHandlerCount(t, 1, uniqueErrs*errFrequency)
}

func checkGlobalDedupingErrorHandlerCount(t *testing.T, unique int, frequency uint64) {
	t.Helper()

	if length := len(DedupingErrorHandler.count); length != unique {
		t.Errorf("expected length %d got %d", unique, length)
	}

	for key, val := range DedupingErrorHandler.count {
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

func BenchmarkGlobalDedupingErrorHandlerDirectMatch(b *testing.B) {
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

	// only the iterations with the same i should be considered the same error
	for i := 0; i < b.N; i++ {
		HandleError(fmt.Errorf("testwithenoughsamedata%d", i))
	}
}

func BenchmarkGlobalDedupingErrorHandlerFuzzyMatch(b *testing.B) {
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

	// enable fuzzy matching
	DedupingErrorHandler.Similar = 0.75

	// now these should all be considered the same error
	for i := 0; i < b.N; i++ {
		HandleError(fmt.Errorf("testwithenoughsamedata%d", i))
	}
}

var testRudimentaryErrorBackoff = &rudimentaryErrorBackoff{
	lastErrorTime: time.Now(),
	minPeriod:     time.Millisecond,
}

func BenchmarkGlobalDedupingErrorHandlerBaseline(b *testing.B) {
	// this lets us determine the overhead of dedupingErrorHandler
	for i := 0; i < b.N; i++ {
		testRudimentaryErrorBackoff.OnError(fmt.Errorf("testwithenoughsamedata%d", i))
	}
}

type stringErr string

func (s stringErr) Error() string {
	return string(s)
}

type logErrTracker struct {
	t      *testing.T
	called int
}

func (l *logErrTracker) logErr(err error, count uint64) {
	l.called++
}

func (l *logErrTracker) check(called int) {
	l.t.Helper()
	if l.called != called {
		l.t.Errorf("expected %d got %d", called, l.called)
	}
}

func TestDedupingErrorHandlerDirectMatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(t *testing.T, handler *dedupingErrorHandler, tracker *logErrTracker)
	}{
		{
			name: "simple unique errors",
			check: func(t *testing.T, handler *dedupingErrorHandler, tracker *logErrTracker) {
				err1 := fmt.Errorf("1")
				err2 := fmt.Errorf("2")
				err3 := fmt.Errorf("3")

				handler.handleErr(err1)
				handler.handleErr(err2)
				handler.handleErr(err3)

				checkCount(t, handler, map[error]int{
					err1: 1,
					err2: 1,
					err3: 1,
				})
				checkCache(t, handler, 3)
				tracker.check(3)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// setup a test version of dedupingErrorHandler
			d := newDedupingErrorHandler(10, 0, delta, 1)
			d.clock = clock.NewFakeClock(time.Time{})
			l := &logErrTracker{t: t}
			d.logErrorHandler = l.logErr
			d.getStackHandler = func() (stack string) { return "" } // make all errors have the same stack

			// run the test and check results
			tc.check(t, d, l)
		})
	}
}

func TestDedupingErrorHandlerFuzzyMatch(t *testing.T) {
	// TODO
}

func TestDedupingErrorHandlerGetStack(t *testing.T) {
	// TODO
}

func checkCount(t *testing.T, handler *dedupingErrorHandler, expected map[error]int) {
	t.Helper()

	if len(handler.count) != len(expected) {
		t.Errorf("length mismatch %v %v", handler.count, expected)
	}

	for err, count := range expected {
		key := errKey{
			stack:   "",
			errType: reflect.TypeOf(err),
			message: err.Error(),
		}
		val, ok := handler.count[key]
		if !ok {
			t.Errorf("missing key %#v in %v", err, handler.count)
			continue
		}
		if val.count != uint64(count) {
			t.Errorf("key %#v expected count %d got %d", err, count, val.count)
		}
	}
}

func checkCache(t *testing.T, handler *dedupingErrorHandler, expected int) {
	t.Helper()

	// TODO is it possible to do any check other than Len against the cache that does not mutate it?
	if actual := handler.cache.Len(); actual != expected {
		t.Errorf("expected cache length %d got %d", expected, actual)
	}
}
