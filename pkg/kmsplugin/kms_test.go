package kmsplugin

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
)

// mockAPIError implements smithy.APIError interface for testing
type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string {
	return e.message
}

func (e *mockAPIError) ErrorCode() string {
	return e.code
}

func (e *mockAPIError) ErrorMessage() string {
	return e.message
}

func (e *mockAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultUnknown
}

func TestParseError(t *testing.T) {
	tests := []struct {
		name     string
		isCMK    bool
		err      error
		expected KMSErrorType
	}{
		{
			name:     "nil error",
			isCMK:    false,
			err:      nil,
			expected: KMSErrorTypeNil,
		},
		{
			name:     "non-API error",
			isCMK:    false,
			err:      errors.New("generic error"),
			expected: KMSErrorTypeOther,
		},
		{
			name:     "DisabledException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.DisabledException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "KMSInvalidStateException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.KMSInvalidStateException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "KeyUnavailableException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.KeyUnavailableException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "InvalidArnException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.InvalidArnException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "InvalidGrantIdException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.InvalidGrantIdException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "InvalidGrantTokenException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.InvalidGrantTokenException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "LimitExceededException - CMK",
			isCMK:    true,
			err:      &mockAPIError{code: (&types.LimitExceededException{}).ErrorCode()},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "LimitExceededException - not CMK",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.LimitExceededException{}).ErrorCode()},
			expected: KMSErrorTypeThrottled,
		},
		{
			name:     "InvalidCiphertextException",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.InvalidCiphertextException{}).ErrorCode()},
			expected: KMSErrorTypeCorruption,
		},
		{
			name:     "AccessDeniedException caused by key not existing or missing permissions - 1",
			isCMK:    false,
			err:      &mockAPIError{code: "AccessDeniedException", message: "The ciphertext refers to a customer master key that does not exist"},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "AccessDeniedException caused by key not existing or missing permissions - 2",
			isCMK:    false,
			err:      &mockAPIError{code: "AccessDeniedException", message: "User dummy is not authorized to perform: kms:Decrypt on this resource because the resource does not exist in this Region, no resource-based policies allow access, or a resource-based policy explicitly denies access"},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "Other AccessDeniedException",
			isCMK:    false,
			err:      &mockAPIError{code: "AccessDeniedException", message: "access denied for some other reason"},
			expected: KMSErrorTypeOther,
		},
		{
			name:     "KMSInternalException with timeout message",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.KMSInternalException{}).ErrorCode(), message: "AWS KMS rejected the request because the external key store proxy did not respond in time. Retry the request. If you see this error repeatedly, report it to your external key store proxy administrator"},
			expected: KMSErrorTypeUserInduced,
		},
		{
			name:     "KMSInternalException with other message",
			isCMK:    false,
			err:      &mockAPIError{code: (&types.KMSInternalException{}).ErrorCode(), message: "Some other internal error"},
			expected: KMSErrorTypeOther,
		},
		{
			name:     "wrapped other error",
			isCMK:    false,
			err:      errors.New("wrapped: " + (&mockAPIError{code: (&types.DisabledException{}).ErrorCode()}).Error()),
			expected: KMSErrorTypeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseError(tt.err, tt.isCMK)
			assert.Equal(t, tt.expected, result, "ParseError returned incorrect error type")
		})
	}
}
