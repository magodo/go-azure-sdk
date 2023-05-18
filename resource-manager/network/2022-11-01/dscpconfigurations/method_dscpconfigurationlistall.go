package dscpconfigurations

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/commonids"
	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type DscpConfigurationListAllOperationResponse struct {
	HttpResponse *http.Response
	OData        *odata.OData
	Model        *[]DscpConfiguration
}

type DscpConfigurationListAllCompleteResult struct {
	Items []DscpConfiguration
}

// DscpConfigurationListAll ...
func (c DscpConfigurationsClient) DscpConfigurationListAll(ctx context.Context, id commonids.SubscriptionId) (result DscpConfigurationListAllOperationResponse, err error) {
	opts := client.RequestOptions{
		ContentType: "application/json",
		ExpectedStatusCodes: []int{
			http.StatusOK,
		},
		HttpMethod: http.MethodGet,
		Path:       fmt.Sprintf("%s/providers/Microsoft.Network/dscpConfigurations", id.ID()),
	}

	req, err := c.Client.NewRequest(ctx, opts)
	if err != nil {
		return
	}

	var resp *client.Response
	resp, err = req.ExecutePaged(ctx)
	if resp != nil {
		result.OData = resp.OData
		result.HttpResponse = resp.Response
	}
	if err != nil {
		return
	}

	var values struct {
		Values *[]DscpConfiguration `json:"value"`
	}
	if err = resp.Unmarshal(&values); err != nil {
		return
	}

	result.Model = values.Values

	return
}

// DscpConfigurationListAllComplete retrieves all the results into a single object
func (c DscpConfigurationsClient) DscpConfigurationListAllComplete(ctx context.Context, id commonids.SubscriptionId) (DscpConfigurationListAllCompleteResult, error) {
	return c.DscpConfigurationListAllCompleteMatchingPredicate(ctx, id, DscpConfigurationOperationPredicate{})
}

// DscpConfigurationListAllCompleteMatchingPredicate retrieves all the results and then applies the predicate
func (c DscpConfigurationsClient) DscpConfigurationListAllCompleteMatchingPredicate(ctx context.Context, id commonids.SubscriptionId, predicate DscpConfigurationOperationPredicate) (result DscpConfigurationListAllCompleteResult, err error) {
	items := make([]DscpConfiguration, 0)

	resp, err := c.DscpConfigurationListAll(ctx, id)
	if err != nil {
		err = fmt.Errorf("loading results: %+v", err)
		return
	}
	if resp.Model != nil {
		for _, v := range *resp.Model {
			if predicate.Matches(v) {
				items = append(items, v)
			}
		}
	}

	result = DscpConfigurationListAllCompleteResult{
		Items: items,
	}
	return
}
