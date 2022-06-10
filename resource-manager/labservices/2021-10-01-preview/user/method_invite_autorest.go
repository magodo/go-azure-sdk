package user

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/go-azure-helpers/polling"
)

type InviteOperationResponse struct {
	Poller       polling.LongRunningPoller
	HttpResponse *http.Response
}

// Invite ...
func (c UserClient) Invite(ctx context.Context, id UserId, input InviteBody) (result InviteOperationResponse, err error) {
	req, err := c.preparerForInvite(ctx, id, input)
	if err != nil {
		err = autorest.NewErrorWithError(err, "user.UserClient", "Invite", nil, "Failure preparing request")
		return
	}

	result, err = c.senderForInvite(ctx, req)
	if err != nil {
		err = autorest.NewErrorWithError(err, "user.UserClient", "Invite", result.HttpResponse, "Failure sending request")
		return
	}

	return
}

// InviteThenPoll performs Invite then polls until it's completed
func (c UserClient) InviteThenPoll(ctx context.Context, id UserId, input InviteBody) error {
	result, err := c.Invite(ctx, id, input)
	if err != nil {
		return fmt.Errorf("performing Invite: %+v", err)
	}

	if err := result.Poller.PollUntilDone(); err != nil {
		return fmt.Errorf("polling after Invite: %+v", err)
	}

	return nil
}

// preparerForInvite prepares the Invite request.
func (c UserClient) preparerForInvite(ctx context.Context, id UserId, input InviteBody) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(fmt.Sprintf("%s/invite", id.ID())),
		autorest.WithJSON(input),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// senderForInvite sends the Invite request. The method will close the
// http.Response Body if it receives an error.
func (c UserClient) senderForInvite(ctx context.Context, req *http.Request) (future InviteOperationResponse, err error) {
	var resp *http.Response
	resp, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		return
	}
	future.Poller, err = polling.NewLongRunningPollerFromResponse(ctx, resp, c.Client)
	return
}
