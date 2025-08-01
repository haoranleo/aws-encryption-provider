/*
Copyright 2020 The Kubernetes Authors.
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

package plugin

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"go.uber.org/zap"
	pb "k8s.io/kms/apis/v2"
	"sigs.k8s.io/aws-encryption-provider/pkg/cloud"
	"sigs.k8s.io/aws-encryption-provider/pkg/kmsplugin"
)

func TestPluginV2(t *testing.T) {
	tt := []struct {
		input     string
		ctx       map[string]string
		isCMK     bool
		output    string
		err       error
		errType   kmsplugin.KMSErrorType
		healthErr bool
		checkErr  bool
	}{
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    encryptedMessage,
			err:       nil,
			errType:   kmsplugin.KMSErrorTypeNil,
			healthErr: false,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       errorMessage,
			errType:   kmsplugin.KMSErrorTypeOther,
			healthErr: true,
			checkErr:  true,
		},
		{
			input:  plainMessage,
			ctx:    nil,
			isCMK:  false,
			output: "",
			err: &smithy.GenericAPIError{
				Code:    "RequestLimitExceeded",
				Message: "test",
				Fault:   0,
			},
			errType:   kmsplugin.KMSErrorTypeThrottled,
			healthErr: true,
			checkErr:  true,
		},
		{
			input:  plainMessage,
			ctx:    nil,
			isCMK:  true,
			output: "",
			err: &smithy.GenericAPIError{
				Code:    "RequestLimitExceeded",
				Message: "test",
				Fault:   0,
			},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.KMSInternalException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeOther,
			healthErr: true,
			checkErr:  true,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.LimitExceededException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeThrottled,
			healthErr: true,
			checkErr:  true,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     true,
			output:    "",
			err:       &kmstypes.LimitExceededException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:  plainMessage,
			ctx:    nil,
			isCMK:  false,
			output: "",
			err: &smithy.GenericAPIError{
				Code:    "AccessDeniedException",
				Message: "The ciphertext refers to a customer master key that does not exist, does not exist in this region, or you are not allowed to access",
				Fault:   0,
			},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:  plainMessage,
			ctx:    nil,
			isCMK:  false,
			output: "",
			err: &smithy.GenericAPIError{
				Code:    "AccessDeniedException",
				Message: "Some other error message",
				Fault:   0,
			},
			errType:   kmsplugin.KMSErrorTypeOther,
			healthErr: true,
			checkErr:  true,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.DisabledException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.KMSInvalidStateException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.InvalidGrantIdException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.InvalidGrantTokenException{Message: aws.String("test")},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       make(map[string]string),
			isCMK:     false,
			output:    encryptedMessage,
			err:       nil,
			errType:   kmsplugin.KMSErrorTypeNil,
			healthErr: false,
			checkErr:  false,
		},
		{
			input:     encryptedMessage,
			ctx:       map[string]string{"a": "b"},
			isCMK:     false,
			output:    "",
			err:       errors.New("invalid context"),
			errType:   kmsplugin.KMSErrorTypeOther,
			healthErr: true,
			checkErr:  true,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.KMSInternalException{Message: aws.String("AWS KMS rejected the request because the external key store proxy did not respond in time. Retry the request. If you see this error repeatedly, report it to your external key store proxy administrator")},
			errType:   kmsplugin.KMSErrorTypeUserInduced,
			healthErr: true,
			checkErr:  false,
		},
		{
			input:     plainMessage,
			ctx:       nil,
			isCMK:     false,
			output:    "",
			err:       &kmstypes.InvalidCiphertextException{Message: aws.String("InvalidCipherException:")},
			errType:   kmsplugin.KMSErrorTypeCorruption,
			healthErr: true,
			checkErr:  true,
		},
	}

	c := &cloud.KMSMock{}
	ctx := context.Background()

	for idx, tc := range tt {
		encryptTestFunc := func(p *V2Plugin) {
			eReq := &pb.EncryptRequest{Plaintext: []byte(tc.input)}
			eRes, err := p.Encrypt(ctx, eReq)

			if tc.err != nil && err == nil {
				t.Fatalf("#%d: failed to return expected error %v", idx, tc.err)
			}

			if tc.err == nil && err != nil {
				t.Fatalf("#%d: returned unexpected error: %v", idx, err)
			}

			if tc.err == nil && string(eRes.Ciphertext) != kmsplugin.StorageVersion+tc.output {
				t.Fatalf("#%d: expected %s, but got %s", idx, kmsplugin.StorageVersion+tc.output, string(eRes.Ciphertext))
			}

			et := kmsplugin.ParseError(tc.err, p.isCMK)
			if !reflect.DeepEqual(tc.errType, et) {
				t.Fatalf("#%d: expected error type %s, got %s", idx, tc.errType, et)
			}
		}
		decryptTestFunc := func(p *V2Plugin) {
			dReq := &pb.DecryptRequest{Ciphertext: []byte(kmsplugin.StorageVersion + tc.output)}
			dRes, err := p.Decrypt(ctx, dReq)

			if tc.err != nil && err == nil {
				t.Fatalf("#%d: failed to return expected error %v", idx, tc.err)
			}

			if tc.err == nil && err != nil {
				t.Fatalf("#%d: returned unexpected error: %v", idx, err)
			}

			if tc.err == nil && string(dRes.Plaintext) != tc.input {
				t.Fatalf("#%d: expected %s, but got %s", idx, tc.input, string(dRes.Plaintext))
			}

			et := kmsplugin.ParseError(tc.err, p.isCMK)
			if !reflect.DeepEqual(tc.errType, et) {
				t.Fatalf("#%d: expected error type %s, got %s", idx, tc.errType, et)
			}
		}

		for _, tf := range []func(p *V2Plugin){encryptTestFunc, decryptTestFunc} {
			func() {
				c.SetEncryptResp(tc.output, tc.err)
				c.SetDecryptResp(tc.input, tc.err)
				sharedHealthCheck := NewSharedHealthCheck(DefaultHealthCheckPeriod, DefaultErrcBufSize)
				go sharedHealthCheck.Start()
				p := NewV2(key, c, nil, sharedHealthCheck, tc.isCMK)
				defer func() {
					sharedHealthCheck.Stop()
				}()
				tf(p)

				herr := p.Health()
				if tc.healthErr && herr == nil {
					t.Fatalf("#%d: expected health error, but got nil", idx)
				}
				if !tc.healthErr && herr != nil {
					t.Fatalf("#%d: unexpected health error, got %v", idx, herr)
				}

				cerr := p.Live()
				if tc.checkErr && cerr == nil {
					t.Fatalf("#%d: expected check error, but got nil", idx)
				}
				if !tc.checkErr && cerr != nil {
					t.Fatalf("#%d: unexpected check error, got %v", idx, cerr)
				}
			}()
		}
	}
}

func TestHealthV2(t *testing.T) {
	plain := "input-text1"
	cipher := "output-text1"
	zap.ReplaceGlobals(zap.NewExample())

	tt := []struct {
		encryptErr       error
		decryptErr       error
		decryptHealthErr bool
		isCMK            bool
	}{
		{
			encryptErr:       nil,
			decryptErr:       nil,
			decryptHealthErr: false,
			isCMK:            false,
		},
		{
			encryptErr:       errors.New("encrypt fail"),
			decryptErr:       errors.New("decrypt fail"),
			decryptHealthErr: true,
			isCMK:            false,
		},
		{
			encryptErr:       &kmstypes.LimitExceededException{Message: aws.String("test")},
			decryptErr:       &kmstypes.LimitExceededException{Message: aws.String("test")},
			decryptHealthErr: true,
			isCMK:            true,
		},
		{
			encryptErr:       nil,
			decryptErr:       &kmstypes.InvalidCiphertextException{Message: aws.String("InvalidCipherException:")},
			decryptHealthErr: false,
			isCMK:            false,
		},
	}
	for idx, entry := range tt {
		c := &cloud.KMSMock{}
		sharedHealthCheck := NewSharedHealthCheck(DefaultHealthCheckPeriod, DefaultErrcBufSize)
		go sharedHealthCheck.Start()
		p := NewV2(key, c, nil, sharedHealthCheck, entry.isCMK)
		defer func() {
			sharedHealthCheck.Stop()
		}()

		c.SetEncryptResp(cipher, entry.encryptErr)
		c.SetDecryptResp(plain, entry.decryptErr)
		c.AddEncryptRule(func(params *kms.EncryptInput) bool {
			return string(params.Plaintext) == "foo"
		}, "foo", nil)
		c.AddDecryptRule(func(params *kms.DecryptInput) bool {
			return string(params.CiphertextBlob) == "foo"
		}, "foo", nil)

		_, encErr := p.Encrypt(context.Background(), &pb.EncryptRequest{Plaintext: []byte(plain)})
		if entry.encryptErr == nil && encErr != nil {
			t.Fatalf("#%d: unexpected error from Encrypt %v", idx, encErr)
		}
		herr1 := p.Health()
		if entry.encryptErr == nil {
			if herr1 != nil {
				t.Fatalf("#%d: unexpected error from Health %v", idx, herr1)
			}
		} else if !strings.HasSuffix(encErr.Error(), entry.encryptErr.Error()) {
			t.Fatalf("#%d: unexpected error from Health %v", idx, herr1)
		}

		_, decErr := p.Decrypt(context.Background(), &pb.DecryptRequest{Ciphertext: []byte("1foo")})
		if entry.decryptErr == nil && decErr != nil {
			t.Fatalf("#%d: unexpected error from Encrypt %v", idx, decErr)
		}
		herr2 := p.Health()
		if !entry.decryptHealthErr {
			if herr2 != nil {
				t.Fatalf("#%d: unexpected error from Health %v", idx, herr2)
			}
		} else if decErr != nil && !strings.HasSuffix(decErr.Error(), entry.decryptErr.Error()) {
			t.Fatalf("#%d: unexpected error from Health %v", idx, herr2)
		}
	}
}

// TestHealthManyRequests sends many requests to fill up the error channel,
// and ensures following encrypt/decrypt operation do not block.
func TestHealthManyRequestsV2(t *testing.T) {
	zap.ReplaceGlobals(zap.NewExample())

	c := &cloud.KMSMock{}
	sharedHealthCheck := NewSharedHealthCheck(DefaultHealthCheckPeriod, DefaultErrcBufSize)
	go sharedHealthCheck.Start()
	p := newPluginV2(key, c, nil, sharedHealthCheck, false)
	defer func() {
		sharedHealthCheck.Stop()
	}()

	c.SetEncryptResp("foo", errors.New("fail"))
	for i := 0; i < 10; i++ {
		errc := make(chan error)
		go func() {
			_, err := p.Encrypt(
				context.Background(),
				&pb.EncryptRequest{Plaintext: []byte("foo")},
			)
			errc <- err
		}()
		select {
		case <-time.After(time.Second):
			t.Fatalf("#%d: Encrypt took longer than it should", i)
		case err := <-errc:
			if !strings.HasSuffix(err.Error(), "fail") {
				t.Fatalf("#%d: unexpected errro %v", i, err)
			}
		}
	}
}
