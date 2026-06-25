package serial

import (
	"fmt"
	"strconv"
	"strings"
)

// ToString serializes an arbitrary value into string.
func ToString(v interface{}) string {
	if v == nil {
		return ""
	}

	switch value := v.(type) {
	case string:
		return value
	case *string:
		return *value
	case int:
		return strconv.Itoa(value)
	case int8:
		return strconv.FormatInt(int64(value), 10)
	case int16:
		return strconv.FormatInt(int64(value), 10)
	case int32:
		return strconv.FormatInt(int64(value), 10)
	case int64:
		return strconv.FormatInt(value, 10)
	case uint:
		return strconv.FormatUint(uint64(value), 10)
	case uint8:
		return strconv.FormatUint(uint64(value), 10)
	case uint16:
		return strconv.FormatUint(uint64(value), 10)
	case uint32:
		return strconv.FormatUint(uint64(value), 10)
	case uint64:
		return strconv.FormatUint(value, 10)
	case bool:
		return strconv.FormatBool(value)
	case fmt.Stringer:
		return value.String()
	case error:
		return value.Error()
	default:
		return fmt.Sprintf("%+v", value)
	}
}

// Concat concatenates all input into a single string.
func Concat(v ...interface{}) string {
	builder := strings.Builder{}
	for _, value := range v {
		builder.WriteString(ToString(value))
	}
	return builder.String()
}
