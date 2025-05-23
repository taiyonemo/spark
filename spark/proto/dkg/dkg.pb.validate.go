// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: dkg.proto

package dkg

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on InitiateDkgRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *InitiateDkgRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on InitiateDkgRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// InitiateDkgRequestMultiError, or nil if none found.
func (m *InitiateDkgRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *InitiateDkgRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for RequestId

	// no validation rules for KeyCount

	// no validation rules for MinSigners

	// no validation rules for MaxSigners

	// no validation rules for CoordinatorIndex

	if len(errors) > 0 {
		return InitiateDkgRequestMultiError(errors)
	}

	return nil
}

// InitiateDkgRequestMultiError is an error wrapping multiple validation errors
// returned by InitiateDkgRequest.ValidateAll() if the designated constraints
// aren't met.
type InitiateDkgRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m InitiateDkgRequestMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m InitiateDkgRequestMultiError) AllErrors() []error { return m }

// InitiateDkgRequestValidationError is the validation error returned by
// InitiateDkgRequest.Validate if the designated constraints aren't met.
type InitiateDkgRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e InitiateDkgRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e InitiateDkgRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e InitiateDkgRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e InitiateDkgRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e InitiateDkgRequestValidationError) ErrorName() string {
	return "InitiateDkgRequestValidationError"
}

// Error satisfies the builtin error interface
func (e InitiateDkgRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sInitiateDkgRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = InitiateDkgRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = InitiateDkgRequestValidationError{}

// Validate checks the field values on InitiateDkgResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *InitiateDkgResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on InitiateDkgResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// InitiateDkgResponseMultiError, or nil if none found.
func (m *InitiateDkgResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *InitiateDkgResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Identifier

	if len(errors) > 0 {
		return InitiateDkgResponseMultiError(errors)
	}

	return nil
}

// InitiateDkgResponseMultiError is an error wrapping multiple validation
// errors returned by InitiateDkgResponse.ValidateAll() if the designated
// constraints aren't met.
type InitiateDkgResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m InitiateDkgResponseMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m InitiateDkgResponseMultiError) AllErrors() []error { return m }

// InitiateDkgResponseValidationError is the validation error returned by
// InitiateDkgResponse.Validate if the designated constraints aren't met.
type InitiateDkgResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e InitiateDkgResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e InitiateDkgResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e InitiateDkgResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e InitiateDkgResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e InitiateDkgResponseValidationError) ErrorName() string {
	return "InitiateDkgResponseValidationError"
}

// Error satisfies the builtin error interface
func (e InitiateDkgResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sInitiateDkgResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = InitiateDkgResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = InitiateDkgResponseValidationError{}

// Validate checks the field values on Round1PackagesRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Round1PackagesRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Round1PackagesRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Round1PackagesRequestMultiError, or nil if none found.
func (m *Round1PackagesRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *Round1PackagesRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for RequestId

	for idx, item := range m.GetRound1Packages() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, Round1PackagesRequestValidationError{
						field:  fmt.Sprintf("Round1Packages[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, Round1PackagesRequestValidationError{
						field:  fmt.Sprintf("Round1Packages[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Round1PackagesRequestValidationError{
					field:  fmt.Sprintf("Round1Packages[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return Round1PackagesRequestMultiError(errors)
	}

	return nil
}

// Round1PackagesRequestMultiError is an error wrapping multiple validation
// errors returned by Round1PackagesRequest.ValidateAll() if the designated
// constraints aren't met.
type Round1PackagesRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Round1PackagesRequestMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Round1PackagesRequestMultiError) AllErrors() []error { return m }

// Round1PackagesRequestValidationError is the validation error returned by
// Round1PackagesRequest.Validate if the designated constraints aren't met.
type Round1PackagesRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Round1PackagesRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Round1PackagesRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Round1PackagesRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Round1PackagesRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Round1PackagesRequestValidationError) ErrorName() string {
	return "Round1PackagesRequestValidationError"
}

// Error satisfies the builtin error interface
func (e Round1PackagesRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRound1PackagesRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Round1PackagesRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Round1PackagesRequestValidationError{}

// Validate checks the field values on Round1PackagesResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Round1PackagesResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Round1PackagesResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Round1PackagesResponseMultiError, or nil if none found.
func (m *Round1PackagesResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *Round1PackagesResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Identifier

	// no validation rules for Round1Signature

	if len(errors) > 0 {
		return Round1PackagesResponseMultiError(errors)
	}

	return nil
}

// Round1PackagesResponseMultiError is an error wrapping multiple validation
// errors returned by Round1PackagesResponse.ValidateAll() if the designated
// constraints aren't met.
type Round1PackagesResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Round1PackagesResponseMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Round1PackagesResponseMultiError) AllErrors() []error { return m }

// Round1PackagesResponseValidationError is the validation error returned by
// Round1PackagesResponse.Validate if the designated constraints aren't met.
type Round1PackagesResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Round1PackagesResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Round1PackagesResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Round1PackagesResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Round1PackagesResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Round1PackagesResponseValidationError) ErrorName() string {
	return "Round1PackagesResponseValidationError"
}

// Error satisfies the builtin error interface
func (e Round1PackagesResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRound1PackagesResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Round1PackagesResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Round1PackagesResponseValidationError{}

// Validate checks the field values on Round1SignatureRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Round1SignatureRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Round1SignatureRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Round1SignatureRequestMultiError, or nil if none found.
func (m *Round1SignatureRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *Round1SignatureRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for RequestId

	// no validation rules for Round1Signatures

	if len(errors) > 0 {
		return Round1SignatureRequestMultiError(errors)
	}

	return nil
}

// Round1SignatureRequestMultiError is an error wrapping multiple validation
// errors returned by Round1SignatureRequest.ValidateAll() if the designated
// constraints aren't met.
type Round1SignatureRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Round1SignatureRequestMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Round1SignatureRequestMultiError) AllErrors() []error { return m }

// Round1SignatureRequestValidationError is the validation error returned by
// Round1SignatureRequest.Validate if the designated constraints aren't met.
type Round1SignatureRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Round1SignatureRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Round1SignatureRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Round1SignatureRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Round1SignatureRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Round1SignatureRequestValidationError) ErrorName() string {
	return "Round1SignatureRequestValidationError"
}

// Error satisfies the builtin error interface
func (e Round1SignatureRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRound1SignatureRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Round1SignatureRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Round1SignatureRequestValidationError{}

// Validate checks the field values on Round1SignatureResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Round1SignatureResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Round1SignatureResponse with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Round1SignatureResponseMultiError, or nil if none found.
func (m *Round1SignatureResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *Round1SignatureResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Identifier

	if len(errors) > 0 {
		return Round1SignatureResponseMultiError(errors)
	}

	return nil
}

// Round1SignatureResponseMultiError is an error wrapping multiple validation
// errors returned by Round1SignatureResponse.ValidateAll() if the designated
// constraints aren't met.
type Round1SignatureResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Round1SignatureResponseMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Round1SignatureResponseMultiError) AllErrors() []error { return m }

// Round1SignatureResponseValidationError is the validation error returned by
// Round1SignatureResponse.Validate if the designated constraints aren't met.
type Round1SignatureResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Round1SignatureResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Round1SignatureResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Round1SignatureResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Round1SignatureResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Round1SignatureResponseValidationError) ErrorName() string {
	return "Round1SignatureResponseValidationError"
}

// Error satisfies the builtin error interface
func (e Round1SignatureResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRound1SignatureResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Round1SignatureResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Round1SignatureResponseValidationError{}

// Validate checks the field values on Round2PackagesRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Round2PackagesRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Round2PackagesRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Round2PackagesRequestMultiError, or nil if none found.
func (m *Round2PackagesRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *Round2PackagesRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for RequestId

	// no validation rules for Identifier

	// no validation rules for Round2Signature

	if len(errors) > 0 {
		return Round2PackagesRequestMultiError(errors)
	}

	return nil
}

// Round2PackagesRequestMultiError is an error wrapping multiple validation
// errors returned by Round2PackagesRequest.ValidateAll() if the designated
// constraints aren't met.
type Round2PackagesRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Round2PackagesRequestMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Round2PackagesRequestMultiError) AllErrors() []error { return m }

// Round2PackagesRequestValidationError is the validation error returned by
// Round2PackagesRequest.Validate if the designated constraints aren't met.
type Round2PackagesRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Round2PackagesRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Round2PackagesRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Round2PackagesRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Round2PackagesRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Round2PackagesRequestValidationError) ErrorName() string {
	return "Round2PackagesRequestValidationError"
}

// Error satisfies the builtin error interface
func (e Round2PackagesRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRound2PackagesRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Round2PackagesRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Round2PackagesRequestValidationError{}

// Validate checks the field values on Round2PackagesResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Round2PackagesResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Round2PackagesResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Round2PackagesResponseMultiError, or nil if none found.
func (m *Round2PackagesResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *Round2PackagesResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return Round2PackagesResponseMultiError(errors)
	}

	return nil
}

// Round2PackagesResponseMultiError is an error wrapping multiple validation
// errors returned by Round2PackagesResponse.ValidateAll() if the designated
// constraints aren't met.
type Round2PackagesResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Round2PackagesResponseMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Round2PackagesResponseMultiError) AllErrors() []error { return m }

// Round2PackagesResponseValidationError is the validation error returned by
// Round2PackagesResponse.Validate if the designated constraints aren't met.
type Round2PackagesResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Round2PackagesResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Round2PackagesResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Round2PackagesResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Round2PackagesResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Round2PackagesResponseValidationError) ErrorName() string {
	return "Round2PackagesResponseValidationError"
}

// Error satisfies the builtin error interface
func (e Round2PackagesResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRound2PackagesResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Round2PackagesResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Round2PackagesResponseValidationError{}

// Validate checks the field values on StartDkgRequest with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *StartDkgRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on StartDkgRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// StartDkgRequestMultiError, or nil if none found.
func (m *StartDkgRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *StartDkgRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Count

	if len(errors) > 0 {
		return StartDkgRequestMultiError(errors)
	}

	return nil
}

// StartDkgRequestMultiError is an error wrapping multiple validation errors
// returned by StartDkgRequest.ValidateAll() if the designated constraints
// aren't met.
type StartDkgRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m StartDkgRequestMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m StartDkgRequestMultiError) AllErrors() []error { return m }

// StartDkgRequestValidationError is the validation error returned by
// StartDkgRequest.Validate if the designated constraints aren't met.
type StartDkgRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e StartDkgRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e StartDkgRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e StartDkgRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e StartDkgRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e StartDkgRequestValidationError) ErrorName() string { return "StartDkgRequestValidationError" }

// Error satisfies the builtin error interface
func (e StartDkgRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStartDkgRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = StartDkgRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = StartDkgRequestValidationError{}
