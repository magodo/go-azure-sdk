package reservationdetails

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

type ReservationsDetailsListByReservationOrderAndReservationOperationResponse struct {
	HttpResponse *http.Response
	Model        *[]ReservationDetail

	nextLink     *string
	nextPageFunc func(ctx context.Context, nextLink string) (ReservationsDetailsListByReservationOrderAndReservationOperationResponse, error)
}

type ReservationsDetailsListByReservationOrderAndReservationCompleteResult struct {
	Items []ReservationDetail
}

func (r ReservationsDetailsListByReservationOrderAndReservationOperationResponse) HasMore() bool {
	return r.nextLink != nil
}

func (r ReservationsDetailsListByReservationOrderAndReservationOperationResponse) LoadMore(ctx context.Context) (resp ReservationsDetailsListByReservationOrderAndReservationOperationResponse, err error) {
	if !r.HasMore() {
		err = fmt.Errorf("no more pages returned")
		return
	}
	return r.nextPageFunc(ctx, *r.nextLink)
}

type ReservationsDetailsListByReservationOrderAndReservationOperationOptions struct {
	Filter *string
}

func DefaultReservationsDetailsListByReservationOrderAndReservationOperationOptions() ReservationsDetailsListByReservationOrderAndReservationOperationOptions {
	return ReservationsDetailsListByReservationOrderAndReservationOperationOptions{}
}

func (o ReservationsDetailsListByReservationOrderAndReservationOperationOptions) toHeaders() map[string]interface{} {
	out := make(map[string]interface{})

	return out
}

func (o ReservationsDetailsListByReservationOrderAndReservationOperationOptions) toQueryString() map[string]interface{} {
	out := make(map[string]interface{})

	if o.Filter != nil {
		out["$filter"] = *o.Filter
	}

	return out
}

// ReservationsDetailsListByReservationOrderAndReservation ...
func (c ReservationDetailsClient) ReservationsDetailsListByReservationOrderAndReservation(ctx context.Context, id ReservationId, options ReservationsDetailsListByReservationOrderAndReservationOperationOptions) (resp ReservationsDetailsListByReservationOrderAndReservationOperationResponse, err error) {
	req, err := c.preparerForReservationsDetailsListByReservationOrderAndReservation(ctx, id, options)
	if err != nil {
		err = autorest.NewErrorWithError(err, "reservationdetails.ReservationDetailsClient", "ReservationsDetailsListByReservationOrderAndReservation", nil, "Failure preparing request")
		return
	}

	resp.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		err = autorest.NewErrorWithError(err, "reservationdetails.ReservationDetailsClient", "ReservationsDetailsListByReservationOrderAndReservation", resp.HttpResponse, "Failure sending request")
		return
	}

	resp, err = c.responderForReservationsDetailsListByReservationOrderAndReservation(resp.HttpResponse)
	if err != nil {
		err = autorest.NewErrorWithError(err, "reservationdetails.ReservationDetailsClient", "ReservationsDetailsListByReservationOrderAndReservation", resp.HttpResponse, "Failure responding to request")
		return
	}
	return
}

// preparerForReservationsDetailsListByReservationOrderAndReservation prepares the ReservationsDetailsListByReservationOrderAndReservation request.
func (c ReservationDetailsClient) preparerForReservationsDetailsListByReservationOrderAndReservation(ctx context.Context, id ReservationId, options ReservationsDetailsListByReservationOrderAndReservationOperationOptions) (*http.Request, error) {
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
		autorest.WithPath(fmt.Sprintf("%s/providers/Microsoft.Consumption/reservationDetails", id.ID())),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// preparerForReservationsDetailsListByReservationOrderAndReservationWithNextLink prepares the ReservationsDetailsListByReservationOrderAndReservation request with the given nextLink token.
func (c ReservationDetailsClient) preparerForReservationsDetailsListByReservationOrderAndReservationWithNextLink(ctx context.Context, nextLink string) (*http.Request, error) {
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

// responderForReservationsDetailsListByReservationOrderAndReservation handles the response to the ReservationsDetailsListByReservationOrderAndReservation request. The method always
// closes the http.Response Body.
func (c ReservationDetailsClient) responderForReservationsDetailsListByReservationOrderAndReservation(resp *http.Response) (result ReservationsDetailsListByReservationOrderAndReservationOperationResponse, err error) {
	type page struct {
		Values   []ReservationDetail `json:"value"`
		NextLink *string             `json:"nextLink"`
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
		result.nextPageFunc = func(ctx context.Context, nextLink string) (result ReservationsDetailsListByReservationOrderAndReservationOperationResponse, err error) {
			req, err := c.preparerForReservationsDetailsListByReservationOrderAndReservationWithNextLink(ctx, nextLink)
			if err != nil {
				err = autorest.NewErrorWithError(err, "reservationdetails.ReservationDetailsClient", "ReservationsDetailsListByReservationOrderAndReservation", nil, "Failure preparing request")
				return
			}

			result.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
			if err != nil {
				err = autorest.NewErrorWithError(err, "reservationdetails.ReservationDetailsClient", "ReservationsDetailsListByReservationOrderAndReservation", result.HttpResponse, "Failure sending request")
				return
			}

			result, err = c.responderForReservationsDetailsListByReservationOrderAndReservation(result.HttpResponse)
			if err != nil {
				err = autorest.NewErrorWithError(err, "reservationdetails.ReservationDetailsClient", "ReservationsDetailsListByReservationOrderAndReservation", result.HttpResponse, "Failure responding to request")
				return
			}

			return
		}
	}
	return
}

// ReservationsDetailsListByReservationOrderAndReservationComplete retrieves all of the results into a single object
func (c ReservationDetailsClient) ReservationsDetailsListByReservationOrderAndReservationComplete(ctx context.Context, id ReservationId, options ReservationsDetailsListByReservationOrderAndReservationOperationOptions) (ReservationsDetailsListByReservationOrderAndReservationCompleteResult, error) {
	return c.ReservationsDetailsListByReservationOrderAndReservationCompleteMatchingPredicate(ctx, id, options, ReservationDetailOperationPredicate{})
}

// ReservationsDetailsListByReservationOrderAndReservationCompleteMatchingPredicate retrieves all of the results and then applied the predicate
func (c ReservationDetailsClient) ReservationsDetailsListByReservationOrderAndReservationCompleteMatchingPredicate(ctx context.Context, id ReservationId, options ReservationsDetailsListByReservationOrderAndReservationOperationOptions, predicate ReservationDetailOperationPredicate) (resp ReservationsDetailsListByReservationOrderAndReservationCompleteResult, err error) {
	items := make([]ReservationDetail, 0)

	page, err := c.ReservationsDetailsListByReservationOrderAndReservation(ctx, id, options)
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

	out := ReservationsDetailsListByReservationOrderAndReservationCompleteResult{
		Items: items,
	}
	return out, nil
}
