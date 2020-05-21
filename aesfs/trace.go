package aesfs

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/billziss-gh/cgofuse/fuse"
	log "github.com/sirupsen/logrus"
)

var ENABLE_TRACE = true

func traceJoin(deref bool, vals ...interface{}) string {
	res := []string{}
	for _, v := range vals {
		if deref {
			switch i := v.(type) {
			case *bool:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *int:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *int8:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *int16:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *int32:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *int64:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *uint:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *uint8:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *uint16:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *uint32:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *uint64:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *uintptr:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *float32:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *float64:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *complex64:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *complex128:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *string:
				res = append(res, fmt.Sprintf("%#v", *i))
			case *error:
				res = append(res, fmt.Sprintf("%#v", *i))
			case []byte:
				if len(i) > 16 {
					res = append(res, fmt.Sprintf("[% 02x ...] (len = %d)", i[:16], len(i)))
				} else {
					res = append(res, fmt.Sprintf("[% 02x]", i))
				}
			case *[]byte:
				if len(*i) > 16 {
					res = append(res, fmt.Sprintf("[% 02x ...] (len = %d)", (*i)[:16], len(*i)))
				} else {
					res = append(res, fmt.Sprintf("[% 02x]", *i))
				}
			default:
				res = append(res, fmt.Sprintf("%#v", v))
			}
		} else {
			switch i := v.(type) {
			case []byte:
				if len(i) > 16 {
					res = append(res, fmt.Sprintf("[% 02x ...] (len = %d)", i[:16], len(i)))
				} else {
					res = append(res, fmt.Sprintf("[% 02x]", i))
				}
			default:
				res = append(res, fmt.Sprintf("%#v", v))
			}
		}
	}
	return strings.Join(res, ", ")
}

func Trace(params ...interface{}) func(err *error, errno *int, vals ...interface{}) {
	if !ENABLE_TRACE {
		return func(err *error, errno *int, vals ...interface{}) {}
	}

	// get function name
	pc, _, _, ok := runtime.Caller(1)
	funcName := "<UNKNOWN>"
	if ok {
		fn := runtime.FuncForPC(pc)
		rawFuncName := fn.Name()
		parts := strings.Split(rawFuncName, ".")
		funcName = parts[len(parts)-1]
	}

	uid, gid, _ := fuse.Getcontext()
	prefix := fmt.Sprintf("[u=%d,g=%d]", uid, gid)
	args := traceJoin(false, params...)

	return func(err *error, errno *int, vals ...interface{}) {
		result := ""
		recovered := recover()

		realVals := append([]interface{}{err, errno}, vals...)
		if recovered != nil {
			result = fmt.Sprintf("!PANIC:%v", recovered)
		} else {
			result = fmt.Sprintf("(%v)", traceJoin(true, realVals...))
		}

		form := "%v %v(%v) = %v"
		if recovered != nil {
			log.Errorf(form, prefix, funcName, args, result)
			log.Error("Stack trace:\n" + string(debug.Stack()))
			panic(recovered)
		} else {
			if *err != nil || *errno < 0 {
				log.Warnf(form, prefix, funcName, args, result)
			} else {
				log.Infof(form, prefix, funcName, args, result)
			}
		}
	}
}
