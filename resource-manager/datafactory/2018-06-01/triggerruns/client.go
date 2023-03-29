package triggerruns

import "github.com/Azure/go-autorest/autorest"

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type TriggerrunsClient struct {
	Client  autorest.Client
	baseUri string
}

func NewTriggerrunsClientWithBaseURI(endpoint string) TriggerrunsClient {
	return TriggerrunsClient{
		Client:  autorest.NewClientWithUserAgent(userAgent()),
		baseUri: endpoint,
	}
}
