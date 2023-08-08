package appserviceenvironments

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ resourceids.ResourceId = WorkerPoolInstanceId{}

// WorkerPoolInstanceId is a struct representing the Resource ID for a Worker Pool Instance
type WorkerPoolInstanceId struct {
	SubscriptionId         string
	ResourceGroupName      string
	HostingEnvironmentName string
	WorkerPoolName         string
	InstanceName           string
}

// NewWorkerPoolInstanceID returns a new WorkerPoolInstanceId struct
func NewWorkerPoolInstanceID(subscriptionId string, resourceGroupName string, hostingEnvironmentName string, workerPoolName string, instanceName string) WorkerPoolInstanceId {
	return WorkerPoolInstanceId{
		SubscriptionId:         subscriptionId,
		ResourceGroupName:      resourceGroupName,
		HostingEnvironmentName: hostingEnvironmentName,
		WorkerPoolName:         workerPoolName,
		InstanceName:           instanceName,
	}
}

// ParseWorkerPoolInstanceID parses 'input' into a WorkerPoolInstanceId
func ParseWorkerPoolInstanceID(input string) (*WorkerPoolInstanceId, error) {
	parser := resourceids.NewParserFromResourceIdType(WorkerPoolInstanceId{})
	parsed, err := parser.Parse(input, false)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := WorkerPoolInstanceId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "subscriptionId", *parsed)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "resourceGroupName", *parsed)
	}

	if id.HostingEnvironmentName, ok = parsed.Parsed["hostingEnvironmentName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "hostingEnvironmentName", *parsed)
	}

	if id.WorkerPoolName, ok = parsed.Parsed["workerPoolName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "workerPoolName", *parsed)
	}

	if id.InstanceName, ok = parsed.Parsed["instanceName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "instanceName", *parsed)
	}

	return &id, nil
}

// ParseWorkerPoolInstanceIDInsensitively parses 'input' case-insensitively into a WorkerPoolInstanceId
// note: this method should only be used for API response data and not user input
func ParseWorkerPoolInstanceIDInsensitively(input string) (*WorkerPoolInstanceId, error) {
	parser := resourceids.NewParserFromResourceIdType(WorkerPoolInstanceId{})
	parsed, err := parser.Parse(input, true)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := WorkerPoolInstanceId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "subscriptionId", *parsed)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "resourceGroupName", *parsed)
	}

	if id.HostingEnvironmentName, ok = parsed.Parsed["hostingEnvironmentName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "hostingEnvironmentName", *parsed)
	}

	if id.WorkerPoolName, ok = parsed.Parsed["workerPoolName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "workerPoolName", *parsed)
	}

	if id.InstanceName, ok = parsed.Parsed["instanceName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "instanceName", *parsed)
	}

	return &id, nil
}

// ValidateWorkerPoolInstanceID checks that 'input' can be parsed as a Worker Pool Instance ID
func ValidateWorkerPoolInstanceID(input interface{}, key string) (warnings []string, errors []error) {
	v, ok := input.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected %q to be a string", key))
		return
	}

	if _, err := ParseWorkerPoolInstanceID(v); err != nil {
		errors = append(errors, err)
	}

	return
}

// ID returns the formatted Worker Pool Instance ID
func (id WorkerPoolInstanceId) ID() string {
	fmtString := "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/hostingEnvironments/%s/workerPools/%s/instances/%s"
	return fmt.Sprintf(fmtString, id.SubscriptionId, id.ResourceGroupName, id.HostingEnvironmentName, id.WorkerPoolName, id.InstanceName)
}

// Segments returns a slice of Resource ID Segments which comprise this Worker Pool Instance ID
func (id WorkerPoolInstanceId) Segments() []resourceids.Segment {
	return []resourceids.Segment{
		resourceids.StaticSegment("staticSubscriptions", "subscriptions", "subscriptions"),
		resourceids.SubscriptionIdSegment("subscriptionId", "12345678-1234-9876-4563-123456789012"),
		resourceids.StaticSegment("staticResourceGroups", "resourceGroups", "resourceGroups"),
		resourceids.ResourceGroupSegment("resourceGroupName", "example-resource-group"),
		resourceids.StaticSegment("staticProviders", "providers", "providers"),
		resourceids.ResourceProviderSegment("staticMicrosoftWeb", "Microsoft.Web", "Microsoft.Web"),
		resourceids.StaticSegment("staticHostingEnvironments", "hostingEnvironments", "hostingEnvironments"),
		resourceids.UserSpecifiedSegment("hostingEnvironmentName", "hostingEnvironmentValue"),
		resourceids.StaticSegment("staticWorkerPools", "workerPools", "workerPools"),
		resourceids.UserSpecifiedSegment("workerPoolName", "workerPoolValue"),
		resourceids.StaticSegment("staticInstances", "instances", "instances"),
		resourceids.UserSpecifiedSegment("instanceName", "instanceValue"),
	}
}

// String returns a human-readable description of this Worker Pool Instance ID
func (id WorkerPoolInstanceId) String() string {
	components := []string{
		fmt.Sprintf("Subscription: %q", id.SubscriptionId),
		fmt.Sprintf("Resource Group Name: %q", id.ResourceGroupName),
		fmt.Sprintf("Hosting Environment Name: %q", id.HostingEnvironmentName),
		fmt.Sprintf("Worker Pool Name: %q", id.WorkerPoolName),
		fmt.Sprintf("Instance Name: %q", id.InstanceName),
	}
	return fmt.Sprintf("Worker Pool Instance (%s)", strings.Join(components, "\n"))
}
