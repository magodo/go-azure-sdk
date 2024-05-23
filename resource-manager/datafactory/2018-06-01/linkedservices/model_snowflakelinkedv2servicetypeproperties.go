package linkedservices

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SnowflakeLinkedV2ServiceTypeProperties struct {
	AccountIdentifier    interface{}                  `json:"accountIdentifier"`
	AuthenticationType   *SnowflakeAuthenticationType `json:"authenticationType,omitempty"`
	ClientId             *interface{}                 `json:"clientId,omitempty"`
	ClientSecret         SecretBase                   `json:"clientSecret"`
	Database             interface{}                  `json:"database"`
	EncryptedCredential  *string                      `json:"encryptedCredential,omitempty"`
	Password             SecretBase                   `json:"password"`
	PrivateKey           SecretBase                   `json:"privateKey"`
	PrivateKeyPassphrase SecretBase                   `json:"privateKeyPassphrase"`
	Scope                *interface{}                 `json:"scope,omitempty"`
	TenantId             *interface{}                 `json:"tenantId,omitempty"`
	User                 *interface{}                 `json:"user,omitempty"`
	Warehouse            interface{}                  `json:"warehouse"`
}

var _ json.Unmarshaler = &SnowflakeLinkedV2ServiceTypeProperties{}

func (s *SnowflakeLinkedV2ServiceTypeProperties) UnmarshalJSON(bytes []byte) error {
	type alias SnowflakeLinkedV2ServiceTypeProperties
	var decoded alias
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling into SnowflakeLinkedV2ServiceTypeProperties: %+v", err)
	}

	s.AccountIdentifier = decoded.AccountIdentifier
	s.AuthenticationType = decoded.AuthenticationType
	s.ClientId = decoded.ClientId
	s.Database = decoded.Database
	s.EncryptedCredential = decoded.EncryptedCredential
	s.Scope = decoded.Scope
	s.TenantId = decoded.TenantId
	s.User = decoded.User
	s.Warehouse = decoded.Warehouse

	var temp map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return fmt.Errorf("unmarshaling SnowflakeLinkedV2ServiceTypeProperties into map[string]json.RawMessage: %+v", err)
	}

	if v, ok := temp["clientSecret"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'ClientSecret' for 'SnowflakeLinkedV2ServiceTypeProperties': %+v", err)
		}
		s.ClientSecret = impl
	}

	if v, ok := temp["password"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'Password' for 'SnowflakeLinkedV2ServiceTypeProperties': %+v", err)
		}
		s.Password = impl
	}

	if v, ok := temp["privateKey"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'PrivateKey' for 'SnowflakeLinkedV2ServiceTypeProperties': %+v", err)
		}
		s.PrivateKey = impl
	}

	if v, ok := temp["privateKeyPassphrase"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'PrivateKeyPassphrase' for 'SnowflakeLinkedV2ServiceTypeProperties': %+v", err)
		}
		s.PrivateKeyPassphrase = impl
	}
	return nil
}
