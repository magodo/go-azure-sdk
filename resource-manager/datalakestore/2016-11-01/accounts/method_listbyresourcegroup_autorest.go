package accounts

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/go-azure-helpers/resourcemanager/commonids"
)

type ListByResourceGroupOperationResponse struct {
	HttpResponse *http.Response
	Model        *[]DataLakeStoreAccountBasic

	nextLink     *string
	nextPageFunc func(ctx context.Context, nextLink string) (ListByResourceGroupOperationResponse, error)
}

type ListByResourceGroupCompleteResult struct {
	Items []DataLakeStoreAccountBasic
}

func (r ListByResourceGroupOperationResponse) HasMore() bool {
	return r.nextLink != nil
}

func (r ListByResourceGroupOperationResponse) LoadMore(ctx context.Context) (resp ListByResourceGroupOperationResponse, err error) {
	if !r.HasMore() {
		err = fmt.Errorf("no more pages returned")
		return
	}
	return r.nextPageFunc(ctx, *r.nextLink)
}

type ListByResourceGroupOperationOptions struct {
	Count   *bool
	Filter  *string
	Orderby *string
	Select  *string
	Skip    *int64
	Top     *int64
}

func DefaultListByResourceGroupOperationOptions() ListByResourceGroupOperationOptions {
	return ListByResourceGroupOperationOptions{}
}

func (o ListByResourceGroupOperationOptions) toHeaders() map[string]interface{} {
	out := make(map[string]interface{})

	return out
}

func (o ListByResourceGroupOperationOptions) toQueryString() map[string]interface{} {
	out := make(map[string]interface{})

	if o.Count != nil {
		out["$count"] = *o.Count
	}

	if o.Filter != nil {
		out["$filter"] = *o.Filter
	}

	if o.Orderby != nil {
		out["$orderby"] = *o.Orderby
	}

	if o.Select != nil {
		out["$select"] = *o.Select
	}

	if o.Skip != nil {
		out["$skip"] = *o.Skip
	}

	if o.Top != nil {
		out["$top"] = *o.Top
	}

	return out
}

// ListByResourceGroup ...
func (c AccountsClient) ListByResourceGroup(ctx context.Context, id commonids.ResourceGroupId, options ListByResourceGroupOperationOptions) (resp ListByResourceGroupOperationResponse, err error) {
	req, err := c.preparerForListByResourceGroup(ctx, id, options)
	if err != nil {
		err = autorest.NewErrorWithError(err, "accounts.AccountsClient", "ListByResourceGroup", nil, "Failure preparing request")
		return
	}

	resp.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		err = autorest.NewErrorWithError(err, "accounts.AccountsClient", "ListByResourceGroup", resp.HttpResponse, "Failure sending request")
		return
	}

	resp, err = c.responderForListByResourceGroup(resp.HttpResponse)
	if err != nil {
		err = autorest.NewErrorWithError(err, "accounts.AccountsClient", "ListByResourceGroup", resp.HttpResponse, "Failure responding to request")
		return
	}
	return
}

// ListByResourceGroupComplete retrieves all of the results into a single object
func (c AccountsClient) ListByResourceGroupComplete(ctx context.Context, id commonids.ResourceGroupId, options ListByResourceGroupOperationOptions) (ListByResourceGroupCompleteResult, error) {
	return c.ListByResourceGroupCompleteMatchingPredicate(ctx, id, options, DataLakeStoreAccountBasicOperationPredicate{})
}

// ListByResourceGroupCompleteMatchingPredicate retrieves all of the results and then applied the predicate
func (c AccountsClient) ListByResourceGroupCompleteMatchingPredicate(ctx context.Context, id commonids.ResourceGroupId, options ListByResourceGroupOperationOptions, predicate DataLakeStoreAccountBasicOperationPredicate) (resp ListByResourceGroupCompleteResult, err error) {
	items := make([]DataLakeStoreAccountBasic, 0)

	page, err := c.ListByResourceGroup(ctx, id, options)
	if err != nil {
		err = fmt.Errorf("loading the initial page: %+v", err)
		return
	}
	if page.Model != nil {
		for _, v := range *page.Model {
			if predicate.Matches(v) {
				items = append(items, v)
			}
		}
	}

	for page.HasMore() {
		page, err = page.LoadMore(ctx)
		if err != nil {
			err = fmt.Errorf("loading the next page: %+v", err)
			return
		}

		if page.Model != nil {
			for _, v := range *page.Model {
				if predicate.Matches(v) {
					items = append(items, v)
				}
			}
		}
	}

	out := ListByResourceGroupCompleteResult{
		Items: items,
	}
	return out, nil
}

// preparerForListByResourceGroup prepares the ListByResourceGroup request.
func (c AccountsClient) preparerForListByResourceGroup(ctx context.Context, id commonids.ResourceGroupId, options ListByResourceGroupOperationOptions) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	for k, v := range options.toQueryString() {
		queryParameters[k] = autorest.Encode("query", v)
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithHeaders(options.toHeaders()),
		autorest.WithPath(fmt.Sprintf("%s/providers/Microsoft.DataLakeStore/accounts", id.ID())),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// preparerForListByResourceGroupWithNextLink prepares the ListByResourceGroup request with the given nextLink token.
func (c AccountsClient) preparerForListByResourceGroupWithNextLink(ctx context.Context, nextLink string) (*http.Request, error) {
	uri, err := url.Parse(nextLink)
	if err != nil {
		return nil, fmt.Errorf("parsing nextLink %q: %+v", nextLink, err)
	}
	queryParameters := map[string]interface{}{}
	for k, v := range uri.Query() {
		if len(v) == 0 {
			continue
		}
		val := v[0]
		val = autorest.Encode("query", val)
		queryParameters[k] = val
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(uri.Path),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// responderForListByResourceGroup handles the response to the ListByResourceGroup request. The method always
// closes the http.Response Body.
func (c AccountsClient) responderForListByResourceGroup(resp *http.Response) (result ListByResourceGroupOperationResponse, err error) {
	type page struct {
		Values   []DataLakeStoreAccountBasic `json:"value"`
		NextLink *string                     `json:"nextLink"`
	}
	var respObj page
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&respObj),
		autorest.ByClosing())
	result.HttpResponse = resp
	result.Model = &respObj.Values
	result.nextLink = respObj.NextLink
	if respObj.NextLink != nil {
		result.nextPageFunc = func(ctx context.Context, nextLink string) (result ListByResourceGroupOperationResponse, err error) {
			req, err := c.preparerForListByResourceGroupWithNextLink(ctx, nextLink)
			if err != nil {
				err = autorest.NewErrorWithError(err, "accounts.AccountsClient", "ListByResourceGroup", nil, "Failure preparing request")
				return
			}

			result.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
			if err != nil {
				err = autorest.NewErrorWithError(err, "accounts.AccountsClient", "ListByResourceGroup", result.HttpResponse, "Failure sending request")
				return
			}

			result, err = c.responderForListByResourceGroup(result.HttpResponse)
			if err != nil {
				err = autorest.NewErrorWithError(err, "accounts.AccountsClient", "ListByResourceGroup", result.HttpResponse, "Failure responding to request")
				return
			}

			return
		}
	}
	return
}
