package linkedservices

import (
	"encoding/json"
	"fmt"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type GoogleBigQueryLinkedServiceTypeProperties struct {
	AdditionalProjects      *interface{}                     `json:"additionalProjects,omitempty"`
	AuthenticationType      GoogleBigQueryAuthenticationType `json:"authenticationType"`
	ClientId                *interface{}                     `json:"clientId,omitempty"`
	ClientSecret            SecretBase                       `json:"clientSecret"`
	Email                   *interface{}                     `json:"email,omitempty"`
	EncryptedCredential     *string                          `json:"encryptedCredential,omitempty"`
	KeyFilePath             *interface{}                     `json:"keyFilePath,omitempty"`
	Project                 interface{}                      `json:"project"`
	RefreshToken            SecretBase                       `json:"refreshToken"`
	RequestGoogleDriveScope *interface{}                     `json:"requestGoogleDriveScope,omitempty"`
	TrustedCertPath         *interface{}                     `json:"trustedCertPath,omitempty"`
	UseSystemTrustStore     *interface{}                     `json:"useSystemTrustStore,omitempty"`
}

var _ json.Unmarshaler = &GoogleBigQueryLinkedServiceTypeProperties{}

func (s *GoogleBigQueryLinkedServiceTypeProperties) UnmarshalJSON(bytes []byte) error {
	type alias GoogleBigQueryLinkedServiceTypeProperties
	var decoded alias
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return fmt.Errorf("unmarshaling into GoogleBigQueryLinkedServiceTypeProperties: %+v", err)
	}

	s.AdditionalProjects = decoded.AdditionalProjects
	s.AuthenticationType = decoded.AuthenticationType
	s.ClientId = decoded.ClientId
	s.Email = decoded.Email
	s.EncryptedCredential = decoded.EncryptedCredential
	s.KeyFilePath = decoded.KeyFilePath
	s.Project = decoded.Project
	s.RequestGoogleDriveScope = decoded.RequestGoogleDriveScope
	s.TrustedCertPath = decoded.TrustedCertPath
	s.UseSystemTrustStore = decoded.UseSystemTrustStore

	var temp map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return fmt.Errorf("unmarshaling GoogleBigQueryLinkedServiceTypeProperties into map[string]json.RawMessage: %+v", err)
	}

	if v, ok := temp["clientSecret"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'ClientSecret' for 'GoogleBigQueryLinkedServiceTypeProperties': %+v", err)
		}
		s.ClientSecret = impl
	}

	if v, ok := temp["refreshToken"]; ok {
		impl, err := unmarshalSecretBaseImplementation(v)
		if err != nil {
			return fmt.Errorf("unmarshaling field 'RefreshToken' for 'GoogleBigQueryLinkedServiceTypeProperties': %+v", err)
		}
		s.RefreshToken = impl
	}
	return nil
}
