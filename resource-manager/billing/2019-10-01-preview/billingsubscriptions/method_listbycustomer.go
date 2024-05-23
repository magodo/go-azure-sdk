package billingsubscriptions

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ListByCustomerOperationResponse struct {
	HttpResponse *http.Response
	OData        *odata.OData
	Model        *[]BillingSubscription
}

type ListByCustomerCompleteResult struct {
	LatestHttpResponse *http.Response
	Items              []BillingSubscription
}

// ListByCustomer ...
func (c BillingSubscriptionsClient) ListByCustomer(ctx context.Context, id CustomerId) (result ListByCustomerOperationResponse, err error) {
	opts := client.RequestOptions{
		ContentType: "application/json; charset=utf-8",
		ExpectedStatusCodes: []int{
			http.StatusOK,
		},
		HttpMethod: http.MethodGet,
		Path:       fmt.Sprintf("%s/billingSubscriptions", id.ID()),
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
		Values *[]BillingSubscription `json:"value"`
	}
	if err = resp.Unmarshal(&values); err != nil {
		return
	}

	result.Model = values.Values

	return
}

// ListByCustomerComplete retrieves all the results into a single object
func (c BillingSubscriptionsClient) ListByCustomerComplete(ctx context.Context, id CustomerId) (ListByCustomerCompleteResult, error) {
	return c.ListByCustomerCompleteMatchingPredicate(ctx, id, BillingSubscriptionOperationPredicate{})
}

// ListByCustomerCompleteMatchingPredicate retrieves all the results and then applies the predicate
func (c BillingSubscriptionsClient) ListByCustomerCompleteMatchingPredicate(ctx context.Context, id CustomerId, predicate BillingSubscriptionOperationPredicate) (result ListByCustomerCompleteResult, err error) {
	items := make([]BillingSubscription, 0)

	resp, err := c.ListByCustomer(ctx, id)
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

	result = ListByCustomerCompleteResult{
		LatestHttpResponse: resp.HttpResponse,
		Items:              items,
	}
	return
}
