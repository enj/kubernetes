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
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/golang/groupcache/lru"
)

var (
	// ReallyCrash controls the behavior of HandleCrash and now defaults
	// true. It's still exposed so components can optionally set to false
	// to restore prior behavior.
	ReallyCrash = true
)

// these constants determine the behavior dedupingErrorHandler
const (
	cacheSize  = 1000
	errorDepth = 4
	similar    = 0.75
)

// PanicHandlers is a list of functions which will be invoked when a panic happens.
var PanicHandlers = []func(interface{}){logPanic}

// HandleCrash simply catches a crash and logs an error. Meant to be called via
// defer.  Additional context-specific handlers can be provided, and will be
// called in case of panic.  HandleCrash actually crashes, after calling the
// handlers and logging the panic message.
//
// TODO: remove this function. We are switching to a world where it's safe for
// apiserver to panic, since it will be restarted by kubelet. At the beginning
// of the Kubernetes project, nothing was going to restart apiserver and so
// catching panics was important. But it's actually much simpler for montoring
// software if we just exit when an unexpected panic happens.
func HandleCrash(additionalHandlers ...func(interface{})) {
	if r := recover(); r != nil {
		for _, fn := range PanicHandlers {
			fn(r)
		}
		for _, fn := range additionalHandlers {
			fn(r)
		}
		if ReallyCrash {
			// Actually proceed to panic.
			panic(r)
		}
	}
}

// logPanic logs the caller tree when a panic occurs.
func logPanic(r interface{}) {
	glog.Errorf("Observed a panic: %#v (%v)\n%v", r, r, getCallers())
}

func getCallers() string {
	callers := ""
	for i := 0; true; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		callers = callers + fmt.Sprintf("%v:%v\n", file, line)
	}

	return callers
}

// ErrorHandlers is a list of functions which will be invoked when an unreturnable
// error occurs.
// TODO(lavalamp): for testability, this and the below HandleError function
// should be packaged up into a testable and reusable object.
var ErrorHandlers = []func(error){
	(&dedupingErrorHandler{
		cache: lru.New(cacheSize),
		count: make(map[countKey]*[]countVal),
	}).handleErr,
}

// HandleError is a method to invoke when a non-user facing piece of code cannot
// return an error and needs to indicate it has been ignored. Invoking this method
// is preferable to logging the error - the default behavior is to log but the
// errors may be sent to a remote server for analysis.
func HandleError(err error) {
	// this is sometimes called with a nil error.  We probably shouldn't fail and should do nothing instead
	if err == nil {
		return
	}

	for _, fn := range ErrorHandlers {
		fn(err)
	}
}

// GetCaller returns the caller of the function that calls it.
func GetCaller() string {
	var pc [1]uintptr
	runtime.Callers(3, pc[:])
	f := runtime.FuncForPC(pc[0])
	if f == nil {
		return fmt.Sprintf("Unable to find caller")
	}
	return f.Name()
}

// RecoverFromPanic replaces the specified error with an error containing the
// original error, and  the call tree when a panic occurs. This enables error
// handlers to handle errors and panics the same way.
func RecoverFromPanic(err *error) {
	if r := recover(); r != nil {
		callers := getCallers()

		*err = fmt.Errorf(
			"recovered from panic %q. (err=%v) Call stack:\n%v",
			r,
			*err,
			callers)
	}
}

type dedupingErrorHandler struct {
	mutex sync.Mutex
	cache *lru.Cache
	count map[countKey]*[]countVal
}

func (d *dedupingErrorHandler) handleErr(err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.cache.OnEvicted == nil {
		d.cache.OnEvicted = func(key lru.Key, _ interface{}) {
			d.deleteFromCount(key.(cacheKey))
		}
	}

	key := countKey{stack: getStack(), rtype: reflect.TypeOf(err)}
	message := err.Error()

	if count, ok := d.findAndIncrement(key, message); !ok {
		d.addNewKey(key, message)
		logError(err, 1)
	} else {
		if isPowerOfTwo(count) {
			logError(err, count)
		}
	}
}

func (d *dedupingErrorHandler) addNewKey(key countKey, message string) {
	d.cache.Add(key.withMessage(message), nil)
	val := countVal{message: message, count: 1}

	vals, ok := d.count[key]
	if !ok {
		d.count[key] = &[]countVal{val}
	} else {
		*vals = append(*vals, val)
	}
}

func (d *dedupingErrorHandler) findAndIncrement(key countKey, message string) (int64, bool) {
	vals, ok := d.count[key]
	if !ok {
		return 0, false
	}
	for i := range *vals {
		val := &((*vals)[i])
		if isSimilar(message, val.message) {
			d.cache.Get(key.withMessage(val.message))
			val.count++
			return val.count, true
		}
	}
	return 0, false
}

func (d *dedupingErrorHandler) deleteFromCount(key cacheKey) {
	vals := d.count[key.countKey]
	for i := range *vals {
		val := &((*vals)[i])
		if val.message == key.message {
			*vals = append((*vals)[:i], (*vals)[i+1:]...)
			break
		}
	}
}

type countKey struct {
	stack string
	rtype reflect.Type
}

func (k countKey) withMessage(message string) cacheKey {
	return cacheKey{countKey: k, message: message}
}

type countVal struct {
	message string
	count   int64
}

type cacheKey struct {
	countKey
	message string
}

func isSimilar(s, t string) bool {
	return ratio(s, t) >= similar
}

// logError prints an error with the call stack of the location it was reported
func logError(err error, count int64) {
	glog.ErrorDepth(errorDepth, err, "\n", "count: ", count, "\n", getStack())
}

func getStack() string {
	return strings.Join(strings.Split(string(debug.Stack()), "\n")[errorDepth*2+5:], "\n")
}

func isPowerOfTwo(n int64) bool {
	return (n & (n - 1)) == 0
}

// levenshtein bits that should be a lib

func ratio(s, t string) float64 {
	s = strings.ToLower(s)
	t = strings.ToLower(t)

	if s == t {
		return 1
	}

	matrix := levenshteinDistanceMatrix(s, t)
	dist := matrix[len(matrix)-1][len(matrix[0])-1]

	sum := len(s) + len(t)
	return float64(sum-dist) / float64(sum)
}

func levenshteinDistanceMatrix(s, t string) [][]int {
	d := make([][]int, len(s)+1)
	for i := range d {
		d[i] = make([]int, len(t)+1)
	}
	for i := range d {
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for j := 1; j <= len(t); j++ {
		for i := 1; i <= len(s); i++ {
			if s[i-1] == t[j-1] {
				d[i][j] = d[i-1][j-1]
			} else {
				min := d[i-1][j]
				if d[i][j-1] < min {
					min = d[i][j-1]
				}
				if d[i-1][j-1] < min {
					min = d[i-1][j-1]
				}
				d[i][j] = min + 1
			}
		}

	}
	return d
}
