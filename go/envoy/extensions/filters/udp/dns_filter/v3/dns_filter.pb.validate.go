// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/filters/udp/dns_filter/v3/dns_filter.proto

package envoy_extensions_filters_udp_dns_filter_v3

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

// Validate checks the field values on DnsFilterConfig with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *DnsFilterConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on DnsFilterConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// DnsFilterConfigMultiError, or nil if none found.
func (m *DnsFilterConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *DnsFilterConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetStatPrefix()) < 1 {
		err := DnsFilterConfigValidationError{
			field:  "StatPrefix",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetServerConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, DnsFilterConfigValidationError{
					field:  "ServerConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, DnsFilterConfigValidationError{
					field:  "ServerConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetServerConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return DnsFilterConfigValidationError{
				field:  "ServerConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetClientConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, DnsFilterConfigValidationError{
					field:  "ClientConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, DnsFilterConfigValidationError{
					field:  "ClientConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetClientConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return DnsFilterConfigValidationError{
				field:  "ClientConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return DnsFilterConfigMultiError(errors)
	}
	return nil
}

// DnsFilterConfigMultiError is an error wrapping multiple validation errors
// returned by DnsFilterConfig.ValidateAll() if the designated constraints
// aren't met.
type DnsFilterConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DnsFilterConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DnsFilterConfigMultiError) AllErrors() []error { return m }

// DnsFilterConfigValidationError is the validation error returned by
// DnsFilterConfig.Validate if the designated constraints aren't met.
type DnsFilterConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DnsFilterConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DnsFilterConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DnsFilterConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DnsFilterConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DnsFilterConfigValidationError) ErrorName() string { return "DnsFilterConfigValidationError" }

// Error satisfies the builtin error interface
func (e DnsFilterConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDnsFilterConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DnsFilterConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DnsFilterConfigValidationError{}

// Validate checks the field values on DnsFilterConfig_ServerContextConfig with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *DnsFilterConfig_ServerContextConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on DnsFilterConfig_ServerContextConfig
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// DnsFilterConfig_ServerContextConfigMultiError, or nil if none found.
func (m *DnsFilterConfig_ServerContextConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *DnsFilterConfig_ServerContextConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	switch m.ConfigSource.(type) {

	case *DnsFilterConfig_ServerContextConfig_InlineDnsTable:

		if all {
			switch v := interface{}(m.GetInlineDnsTable()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, DnsFilterConfig_ServerContextConfigValidationError{
						field:  "InlineDnsTable",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, DnsFilterConfig_ServerContextConfigValidationError{
						field:  "InlineDnsTable",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetInlineDnsTable()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return DnsFilterConfig_ServerContextConfigValidationError{
					field:  "InlineDnsTable",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *DnsFilterConfig_ServerContextConfig_ExternalDnsTable:

		if all {
			switch v := interface{}(m.GetExternalDnsTable()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, DnsFilterConfig_ServerContextConfigValidationError{
						field:  "ExternalDnsTable",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, DnsFilterConfig_ServerContextConfigValidationError{
						field:  "ExternalDnsTable",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetExternalDnsTable()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return DnsFilterConfig_ServerContextConfigValidationError{
					field:  "ExternalDnsTable",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		err := DnsFilterConfig_ServerContextConfigValidationError{
			field:  "ConfigSource",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)

	}

	if len(errors) > 0 {
		return DnsFilterConfig_ServerContextConfigMultiError(errors)
	}
	return nil
}

// DnsFilterConfig_ServerContextConfigMultiError is an error wrapping multiple
// validation errors returned by
// DnsFilterConfig_ServerContextConfig.ValidateAll() if the designated
// constraints aren't met.
type DnsFilterConfig_ServerContextConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DnsFilterConfig_ServerContextConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DnsFilterConfig_ServerContextConfigMultiError) AllErrors() []error { return m }

// DnsFilterConfig_ServerContextConfigValidationError is the validation error
// returned by DnsFilterConfig_ServerContextConfig.Validate if the designated
// constraints aren't met.
type DnsFilterConfig_ServerContextConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DnsFilterConfig_ServerContextConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DnsFilterConfig_ServerContextConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DnsFilterConfig_ServerContextConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DnsFilterConfig_ServerContextConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DnsFilterConfig_ServerContextConfigValidationError) ErrorName() string {
	return "DnsFilterConfig_ServerContextConfigValidationError"
}

// Error satisfies the builtin error interface
func (e DnsFilterConfig_ServerContextConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDnsFilterConfig_ServerContextConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DnsFilterConfig_ServerContextConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DnsFilterConfig_ServerContextConfigValidationError{}

// Validate checks the field values on DnsFilterConfig_ClientContextConfig with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *DnsFilterConfig_ClientContextConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on DnsFilterConfig_ClientContextConfig
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// DnsFilterConfig_ClientContextConfigMultiError, or nil if none found.
func (m *DnsFilterConfig_ClientContextConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *DnsFilterConfig_ClientContextConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if d := m.GetResolverTimeout(); d != nil {
		dur, err := d.AsDuration(), d.CheckValid()
		if err != nil {
			err = DnsFilterConfig_ClientContextConfigValidationError{
				field:  "ResolverTimeout",
				reason: "value is not a valid duration",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		} else {

			gte := time.Duration(1*time.Second + 0*time.Nanosecond)

			if dur < gte {
				err := DnsFilterConfig_ClientContextConfigValidationError{
					field:  "ResolverTimeout",
					reason: "value must be greater than or equal to 1s",
				}
				if !all {
					return err
				}
				errors = append(errors, err)
			}

		}
	}

	for idx, item := range m.GetUpstreamResolvers() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, DnsFilterConfig_ClientContextConfigValidationError{
						field:  fmt.Sprintf("UpstreamResolvers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, DnsFilterConfig_ClientContextConfigValidationError{
						field:  fmt.Sprintf("UpstreamResolvers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return DnsFilterConfig_ClientContextConfigValidationError{
					field:  fmt.Sprintf("UpstreamResolvers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if all {
		switch v := interface{}(m.GetDnsResolutionConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, DnsFilterConfig_ClientContextConfigValidationError{
					field:  "DnsResolutionConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, DnsFilterConfig_ClientContextConfigValidationError{
					field:  "DnsResolutionConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetDnsResolutionConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return DnsFilterConfig_ClientContextConfigValidationError{
				field:  "DnsResolutionConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetMaxPendingLookups() < 1 {
		err := DnsFilterConfig_ClientContextConfigValidationError{
			field:  "MaxPendingLookups",
			reason: "value must be greater than or equal to 1",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return DnsFilterConfig_ClientContextConfigMultiError(errors)
	}
	return nil
}

// DnsFilterConfig_ClientContextConfigMultiError is an error wrapping multiple
// validation errors returned by
// DnsFilterConfig_ClientContextConfig.ValidateAll() if the designated
// constraints aren't met.
type DnsFilterConfig_ClientContextConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DnsFilterConfig_ClientContextConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DnsFilterConfig_ClientContextConfigMultiError) AllErrors() []error { return m }

// DnsFilterConfig_ClientContextConfigValidationError is the validation error
// returned by DnsFilterConfig_ClientContextConfig.Validate if the designated
// constraints aren't met.
type DnsFilterConfig_ClientContextConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DnsFilterConfig_ClientContextConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DnsFilterConfig_ClientContextConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DnsFilterConfig_ClientContextConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DnsFilterConfig_ClientContextConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DnsFilterConfig_ClientContextConfigValidationError) ErrorName() string {
	return "DnsFilterConfig_ClientContextConfigValidationError"
}

// Error satisfies the builtin error interface
func (e DnsFilterConfig_ClientContextConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDnsFilterConfig_ClientContextConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DnsFilterConfig_ClientContextConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DnsFilterConfig_ClientContextConfigValidationError{}
