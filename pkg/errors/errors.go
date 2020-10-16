package errors

import (
	"errors"
	"fmt"
)

// StandardError is a standard error.
type StandardError string

func (e StandardError) Error() string {
	return string(e)
}

// WithArgs accepts errors with parameters.
func (e StandardError) WithArgs(v ...interface{}) error {
	var hasErr, hasNil bool
	for _, vv := range v {
		switch err := vv.(type) {
		case error:
			if err == nil {
				return nil
			}
			hasErr = true
		case nil:
			hasNil = true
		}
	}

	if hasNil && !hasErr {
		return nil
	}

	err := advErr{
		err: fmt.Errorf("%w", e),
		v:   v,
	}

	return err
}

// advErr is an error with parameters.
type advErr struct {
	err error
	v   []interface{}
}

// Error returns error string.
func (e advErr) Error() string {
	return fmt.Sprintf(e.err.Error(), e.v...)
}

// Unwrap returns unwrapped error.
func (e advErr) Unwrap() error {
	return errors.Unwrap(e.err)
}
