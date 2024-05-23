package sqlpoolstransparentdataencryption

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SqlPoolTransparentDataEncryptionsListOperationResponse struct {
	HttpResponse *http.Response
	OData        *odata.OData
	Model        *[]TransparentDataEncryption
}

type SqlPoolTransparentDataEncryptionsListCompleteResult struct {
	LatestHttpResponse *http.Response
	Items              []TransparentDataEncryption
}

// SqlPoolTransparentDataEncryptionsList ...
func (c SqlPoolsTransparentDataEncryptionClient) SqlPoolTransparentDataEncryptionsList(ctx context.Context, id SqlPoolId) (result SqlPoolTransparentDataEncryptionsListOperationResponse, err error) {
	opts := client.RequestOptions{
		ContentType: "application/json; charset=utf-8",
		ExpectedStatusCodes: []int{
			http.StatusOK,
		},
		HttpMethod: http.MethodGet,
		Path:       fmt.Sprintf("%s/transparentDataEncryption", id.ID()),
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
		Values *[]TransparentDataEncryption `json:"value"`
	}
	if err = resp.Unmarshal(&values); err != nil {
		return
	}

	result.Model = values.Values

	return
}

// SqlPoolTransparentDataEncryptionsListComplete retrieves all the results into a single object
func (c SqlPoolsTransparentDataEncryptionClient) SqlPoolTransparentDataEncryptionsListComplete(ctx context.Context, id SqlPoolId) (SqlPoolTransparentDataEncryptionsListCompleteResult, error) {
	return c.SqlPoolTransparentDataEncryptionsListCompleteMatchingPredicate(ctx, id, TransparentDataEncryptionOperationPredicate{})
}

// SqlPoolTransparentDataEncryptionsListCompleteMatchingPredicate retrieves all the results and then applies the predicate
func (c SqlPoolsTransparentDataEncryptionClient) SqlPoolTransparentDataEncryptionsListCompleteMatchingPredicate(ctx context.Context, id SqlPoolId, predicate TransparentDataEncryptionOperationPredicate) (result SqlPoolTransparentDataEncryptionsListCompleteResult, err error) {
	items := make([]TransparentDataEncryption, 0)

	resp, err := c.SqlPoolTransparentDataEncryptionsList(ctx, id)
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

	result = SqlPoolTransparentDataEncryptionsListCompleteResult{
		LatestHttpResponse: resp.HttpResponse,
		Items:              items,
	}
	return
}
