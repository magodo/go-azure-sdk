package put

import (
	"context"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ServiceTasksCreateOrUpdateOperationResponse struct {
	HttpResponse *http.Response
	Model        *ProjectTask
}

// ServiceTasksCreateOrUpdate ...
func (c PUTClient) ServiceTasksCreateOrUpdate(ctx context.Context, id ServiceTaskId, input ProjectTask) (result ServiceTasksCreateOrUpdateOperationResponse, err error) {
	req, err := c.preparerForServiceTasksCreateOrUpdate(ctx, id, input)
	if err != nil {
		err = autorest.NewErrorWithError(err, "put.PUTClient", "ServiceTasksCreateOrUpdate", nil, "Failure preparing request")
		return
	}

	result.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		err = autorest.NewErrorWithError(err, "put.PUTClient", "ServiceTasksCreateOrUpdate", result.HttpResponse, "Failure sending request")
		return
	}

	result, err = c.responderForServiceTasksCreateOrUpdate(result.HttpResponse)
	if err != nil {
		err = autorest.NewErrorWithError(err, "put.PUTClient", "ServiceTasksCreateOrUpdate", result.HttpResponse, "Failure responding to request")
		return
	}

	return
}

// preparerForServiceTasksCreateOrUpdate prepares the ServiceTasksCreateOrUpdate request.
func (c PUTClient) preparerForServiceTasksCreateOrUpdate(ctx context.Context, id ServiceTaskId, input ProjectTask) (*http.Request, error) {
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

// responderForServiceTasksCreateOrUpdate handles the response to the ServiceTasksCreateOrUpdate request. The method always
// closes the http.Response Body.
func (c PUTClient) responderForServiceTasksCreateOrUpdate(resp *http.Response) (result ServiceTasksCreateOrUpdateOperationResponse, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusCreated, http.StatusOK),
		autorest.ByUnmarshallingJSON(&result.Model),
		autorest.ByClosing())
	result.HttpResponse = resp

	return
}
