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
	"regexp"
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

// these constants determine the default behavior of dedupingErrorHandler
const (
	// cacheSize determines how many "unique" errors to track
	cacheSize = 1000
	// errorDepth determines how many callers need to be skipped to find the stack of HandleError's caller
	// HandleError -> ErrorHandlers iteration -> dedupingErrorHandler.handleErr -> dedupingErrorHandler.logError
	errorDepth = 4
	// similar determines if two strings are close enough to be considered equal via levenshtein ratio
	similar = 0.75
)

// ErrorHandlers is a list of functions which will be invoked when an unreturnable
// error occurs.
// TODO(lavalamp): for testability, this and the below HandleError function
// should be packaged up into a testable and reusable object.
var ErrorHandlers = []func(error){
	newDedupingErrorHandler(cacheSize, errorDepth, similar).handleErr,
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

func newDedupingErrorHandler(cacheSize, errorDepth int, similar float64) *dedupingErrorHandler {
	d := &dedupingErrorHandler{
		cache: lru.New(cacheSize),
		count: make(map[countKey]*[]countVal),

		errorDepth: errorDepth,
		similar:    similar,
	}

	d.cache.OnEvicted = func(key lru.Key, _ interface{}) {
		d.deleteFromCount(key.(cacheKey))
	}

	return d
}

// dedupingErrorHandler provides a go routine safe error handler via handleErr.
// It tracks error via the caller stack and the error type and uses a levenshtein ratio to compare err.Error().
// An error is considered unique based on the stack + type + levenshtein comparison.
// To prevent from using an infinite amount of memory, it uses a LRU cache to purge old error values.
type dedupingErrorHandler struct {
	mutex sync.Mutex

	// cache tracks stack + type + message and cleans up old entries in count as they roll off the cache
	cache *lru.Cache
	// count tracks (stack + type) -> [](message + count)
	count map[countKey]*[]countVal

	// errorDepth is how many frames to skip from handleErr
	errorDepth int
	// similar is the levenshtein ratio used to determine equivalence
	similar float64
}

// handleErr logs the given error if it is considered new or "not recently seen"
func (d *dedupingErrorHandler) handleErr(err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	stack := d.getStack()
	key := countKey{stack: stack, errType: reflect.TypeOf(err)}
	message := err.Error()

	if count, ok := d.findAndIncrement(key, message); !ok {
		d.addNewKey(key, message)
		d.logError(err, 1, stack)
	} else {
		if isPowerOfTwo(count) {
			d.logError(err, count, stack)
		}
	}
}

func (d *dedupingErrorHandler) addNewKey(key countKey, message string) {
	d.cache.Add(key.withMessage(message), nil)
	val := countVal{message: message, count: 1}

	vals, ok := d.count[key]
	if !ok || vals == nil {
		d.count[key] = &[]countVal{val}
	} else {
		*vals = append(*vals, val)
	}
}

func (d *dedupingErrorHandler) findAndIncrement(key countKey, message string) (int64, bool) {
	vals, ok := d.count[key]
	if !ok || vals == nil {
		return 0, false
	}
	for i := range *vals {
		val := &((*vals)[i])
		if d.isSimilar(message, val.message) {
			d.cache.Get(key.withMessage(val.message))
			val.count++
			return val.count, true
		}
	}
	return 0, false
}

func (d *dedupingErrorHandler) deleteFromCount(key cacheKey) {
	vals, ok := d.count[key.countKey]
	// this should never happen but lets not panic the server in case we made a mistake
	if !ok || vals == nil {
		return
	}

	// remove the slice entirely if it contains only the associated countVal
	// if the length is 1 then the message should always match, but lets check to be sure
	if len(*vals) == 1 && (*vals)[0].message == key.message {
		delete(d.count, key.countKey)
		return
	}

	for i := range *vals {
		val := &((*vals)[i])
		if val.message == key.message {
			*vals = append((*vals)[:i], (*vals)[i+1:]...)
			break
		}
	}
}

func (d *dedupingErrorHandler) isSimilar(s, t string) bool {
	return ratio(s, t) >= d.similar
}

// logError uses glog to log at the call site of HandleError
// it must be called from dedupingErrorHandler.handleErr
func (d *dedupingErrorHandler) logError(err error, count int64, stack string) {
	glog.ErrorDepth(d.errorDepth, err, "\n", "count: ", count, "\n", stack)
}

var (
	hexNumberRE  = regexp.MustCompile(`0x[0-9a-f]+`)
	emptyAddress = []byte("0x?")
)

// getStack returns the important part of the stack trace
// it must be called from dedupingErrorHandler.handleErr
func (d *dedupingErrorHandler) getStack() string {
	// remove all hex addresses from the stack dump because closures can have volatile values
	stack := string(hexNumberRE.ReplaceAll(debug.Stack(), emptyAddress))
	// strip the redundant stuff at the top of the stack
	// add 1 to error depth for debug.Stack (since it calls runtime.Stack), times the sum by 2 since each frame has 2 lines
	// add 1 for go routine number header
	stackLines := strings.Split(stack, "\n")[(d.errorDepth+1)*2+1:]
	return strings.Join(stackLines, "\n")
}

// countKey tracks uniqueness based on the caller's stack and the type of the error
type countKey struct {
	stack   string
	errType reflect.Type
}

func (k countKey) withMessage(message string) cacheKey {
	return cacheKey{countKey: k, message: message}
}

// countVal tracks hits to a "unique" message associated with a countKey
type countVal struct {
	message string
	count   int64
}

// cacheKey tracks a unique countKey and message combination in the LRU cache
// when a cacheKey is dropped from the cache, it contains all the information
// to remove the associated countVal
type cacheKey struct {
	countKey
	message string
}

func isPowerOfTwo(n int64) bool {
	return (n & (n - 1)) == 0
}

// TODO determine if we should vendor a proper (tested) levenshtein lib

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
