package deployments

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/go-azure-helpers/polling"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type CreateOrUpdateAtScopeOperationResponse struct {
	Poller       polling.LongRunningPoller
	HttpResponse *http.Response
}

// CreateOrUpdateAtScope ...
func (c DeploymentsClient) CreateOrUpdateAtScope(ctx context.Context, id ScopedDeploymentId, input Deployment) (result CreateOrUpdateAtScopeOperationResponse, err error) {
	req, err := c.preparerForCreateOrUpdateAtScope(ctx, id, input)
	if err != nil {
		err = autorest.NewErrorWithError(err, "deployments.DeploymentsClient", "CreateOrUpdateAtScope", nil, "Failure preparing request")
		return
	}

	result, err = c.senderForCreateOrUpdateAtScope(ctx, req)
	if err != nil {
		err = autorest.NewErrorWithError(err, "deployments.DeploymentsClient", "CreateOrUpdateAtScope", result.HttpResponse, "Failure sending request")
		return
	}

	return
}

// CreateOrUpdateAtScopeThenPoll performs CreateOrUpdateAtScope then polls until it's completed
func (c DeploymentsClient) CreateOrUpdateAtScopeThenPoll(ctx context.Context, id ScopedDeploymentId, input Deployment) error {
	result, err := c.CreateOrUpdateAtScope(ctx, id, input)
	if err != nil {
		return fmt.Errorf("performing CreateOrUpdateAtScope: %+v", err)
	}

	if err := result.Poller.PollUntilDone(); err != nil {
		return fmt.Errorf("polling after CreateOrUpdateAtScope: %+v", err)
	}

	return nil
}

// preparerForCreateOrUpdateAtScope prepares the CreateOrUpdateAtScope request.
func (c DeploymentsClient) preparerForCreateOrUpdateAtScope(ctx context.Context, id ScopedDeploymentId, input Deployment) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPut(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(id.ID()),
		autorest.WithJSON(input),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// senderForCreateOrUpdateAtScope sends the CreateOrUpdateAtScope request. The method will close the
// http.Response Body if it receives an error.
func (c DeploymentsClient) senderForCreateOrUpdateAtScope(ctx context.Context, req *http.Request) (future CreateOrUpdateAtScopeOperationResponse, err error) {
	var resp *http.Response
	resp, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		return
	}

	future.Poller, err = polling.NewPollerFromResponse(ctx, resp, c.Client, req.Method)
	return
}
