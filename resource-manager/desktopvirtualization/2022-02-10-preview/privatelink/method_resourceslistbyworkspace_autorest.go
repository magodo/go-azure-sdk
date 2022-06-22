package privatelink

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ResourcesListByWorkspaceOperationResponse struct {
	HttpResponse *http.Response
	Model        *[]PrivateLinkResource

	nextLink     *string
	nextPageFunc func(ctx context.Context, nextLink string) (ResourcesListByWorkspaceOperationResponse, error)
}

type ResourcesListByWorkspaceCompleteResult struct {
	Items []PrivateLinkResource
}

func (r ResourcesListByWorkspaceOperationResponse) HasMore() bool {
	return r.nextLink != nil
}

func (r ResourcesListByWorkspaceOperationResponse) LoadMore(ctx context.Context) (resp ResourcesListByWorkspaceOperationResponse, err error) {
	if !r.HasMore() {
		err = fmt.Errorf("no more pages returned")
		return
	}
	return r.nextPageFunc(ctx, *r.nextLink)
}

// ResourcesListByWorkspace ...
func (c PrivateLinkClient) ResourcesListByWorkspace(ctx context.Context, id WorkspaceId) (resp ResourcesListByWorkspaceOperationResponse, err error) {
	req, err := c.preparerForResourcesListByWorkspace(ctx, id)
	if err != nil {
		err = autorest.NewErrorWithError(err, "privatelink.PrivateLinkClient", "ResourcesListByWorkspace", nil, "Failure preparing request")
		return
	}

	resp.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		err = autorest.NewErrorWithError(err, "privatelink.PrivateLinkClient", "ResourcesListByWorkspace", resp.HttpResponse, "Failure sending request")
		return
	}

	resp, err = c.responderForResourcesListByWorkspace(resp.HttpResponse)
	if err != nil {
		err = autorest.NewErrorWithError(err, "privatelink.PrivateLinkClient", "ResourcesListByWorkspace", resp.HttpResponse, "Failure responding to request")
		return
	}
	return
}

// ResourcesListByWorkspaceComplete retrieves all of the results into a single object
func (c PrivateLinkClient) ResourcesListByWorkspaceComplete(ctx context.Context, id WorkspaceId) (ResourcesListByWorkspaceCompleteResult, error) {
	return c.ResourcesListByWorkspaceCompleteMatchingPredicate(ctx, id, PrivateLinkResourceOperationPredicate{})
}

// ResourcesListByWorkspaceCompleteMatchingPredicate retrieves all of the results and then applied the predicate
func (c PrivateLinkClient) ResourcesListByWorkspaceCompleteMatchingPredicate(ctx context.Context, id WorkspaceId, predicate PrivateLinkResourceOperationPredicate) (resp ResourcesListByWorkspaceCompleteResult, err error) {
	items := make([]PrivateLinkResource, 0)

	page, err := c.ResourcesListByWorkspace(ctx, id)
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

	out := ResourcesListByWorkspaceCompleteResult{
		Items: items,
	}
	return out, nil
}

// preparerForResourcesListByWorkspace prepares the ResourcesListByWorkspace request.
func (c PrivateLinkClient) preparerForResourcesListByWorkspace(ctx context.Context, id WorkspaceId) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsGet(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(fmt.Sprintf("%s/privateLinkResources", id.ID())),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// preparerForResourcesListByWorkspaceWithNextLink prepares the ResourcesListByWorkspace request with the given nextLink token.
func (c PrivateLinkClient) preparerForResourcesListByWorkspaceWithNextLink(ctx context.Context, nextLink string) (*http.Request, error) {
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

// responderForResourcesListByWorkspace handles the response to the ResourcesListByWorkspace request. The method always
// closes the http.Response Body.
func (c PrivateLinkClient) responderForResourcesListByWorkspace(resp *http.Response) (result ResourcesListByWorkspaceOperationResponse, err error) {
	type page struct {
		Values   []PrivateLinkResource `json:"value"`
		NextLink *string               `json:"nextLink"`
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
		result.nextPageFunc = func(ctx context.Context, nextLink string) (result ResourcesListByWorkspaceOperationResponse, err error) {
			req, err := c.preparerForResourcesListByWorkspaceWithNextLink(ctx, nextLink)
			if err != nil {
				err = autorest.NewErrorWithError(err, "privatelink.PrivateLinkClient", "ResourcesListByWorkspace", nil, "Failure preparing request")
				return
			}

			result.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
			if err != nil {
				err = autorest.NewErrorWithError(err, "privatelink.PrivateLinkClient", "ResourcesListByWorkspace", result.HttpResponse, "Failure sending request")
				return
			}

			result, err = c.responderForResourcesListByWorkspace(result.HttpResponse)
			if err != nil {
				err = autorest.NewErrorWithError(err, "privatelink.PrivateLinkClient", "ResourcesListByWorkspace", result.HttpResponse, "Failure responding to request")
				return
			}

			return
		}
	}
	return
}
