package snapshots

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ resourceids.ResourceId = SnapshotId{}

// SnapshotId is a struct representing the Resource ID for a Snapshot
type SnapshotId struct {
	SubscriptionId    string
	ResourceGroupName string
	NetAppAccountName string
	CapacityPoolName  string
	VolumeName        string
	SnapshotName      string
}

// NewSnapshotID returns a new SnapshotId struct
func NewSnapshotID(subscriptionId string, resourceGroupName string, netAppAccountName string, capacityPoolName string, volumeName string, snapshotName string) SnapshotId {
	return SnapshotId{
		SubscriptionId:    subscriptionId,
		ResourceGroupName: resourceGroupName,
		NetAppAccountName: netAppAccountName,
		CapacityPoolName:  capacityPoolName,
		VolumeName:        volumeName,
		SnapshotName:      snapshotName,
	}
}

// ParseSnapshotID parses 'input' into a SnapshotId
func ParseSnapshotID(input string) (*SnapshotId, error) {
	parser := resourceids.NewParserFromResourceIdType(SnapshotId{})
	parsed, err := parser.Parse(input, false)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := SnapshotId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, fmt.Errorf("the segment 'subscriptionId' was not found in the resource id %q", input)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceGroupName' was not found in the resource id %q", input)
	}

	if id.NetAppAccountName, ok = parsed.Parsed["netAppAccountName"]; !ok {
		return nil, fmt.Errorf("the segment 'netAppAccountName' was not found in the resource id %q", input)
	}

	if id.CapacityPoolName, ok = parsed.Parsed["capacityPoolName"]; !ok {
		return nil, fmt.Errorf("the segment 'capacityPoolName' was not found in the resource id %q", input)
	}

	if id.VolumeName, ok = parsed.Parsed["volumeName"]; !ok {
		return nil, fmt.Errorf("the segment 'volumeName' was not found in the resource id %q", input)
	}

	if id.SnapshotName, ok = parsed.Parsed["snapshotName"]; !ok {
		return nil, fmt.Errorf("the segment 'snapshotName' was not found in the resource id %q", input)
	}

	return &id, nil
}

// ParseSnapshotIDInsensitively parses 'input' case-insensitively into a SnapshotId
// note: this method should only be used for API response data and not user input
func ParseSnapshotIDInsensitively(input string) (*SnapshotId, error) {
	parser := resourceids.NewParserFromResourceIdType(SnapshotId{})
	parsed, err := parser.Parse(input, true)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := SnapshotId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, fmt.Errorf("the segment 'subscriptionId' was not found in the resource id %q", input)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceGroupName' was not found in the resource id %q", input)
	}

	if id.NetAppAccountName, ok = parsed.Parsed["netAppAccountName"]; !ok {
		return nil, fmt.Errorf("the segment 'netAppAccountName' was not found in the resource id %q", input)
	}

	if id.CapacityPoolName, ok = parsed.Parsed["capacityPoolName"]; !ok {
		return nil, fmt.Errorf("the segment 'capacityPoolName' was not found in the resource id %q", input)
	}

	if id.VolumeName, ok = parsed.Parsed["volumeName"]; !ok {
		return nil, fmt.Errorf("the segment 'volumeName' was not found in the resource id %q", input)
	}

	if id.SnapshotName, ok = parsed.Parsed["snapshotName"]; !ok {
		return nil, fmt.Errorf("the segment 'snapshotName' was not found in the resource id %q", input)
	}

	return &id, nil
}

// ValidateSnapshotID checks that 'input' can be parsed as a Snapshot ID
func ValidateSnapshotID(input interface{}, key string) (warnings []string, errors []error) {
	v, ok := input.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected %q to be a string", key))
		return
	}

	if _, err := ParseSnapshotID(v); err != nil {
		errors = append(errors, err)
	}

	return
}

// ID returns the formatted Snapshot ID
func (id SnapshotId) ID() string {
	fmtString := "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.NetApp/netAppAccounts/%s/capacityPools/%s/volumes/%s/snapshots/%s"
	return fmt.Sprintf(fmtString, id.SubscriptionId, id.ResourceGroupName, id.NetAppAccountName, id.CapacityPoolName, id.VolumeName, id.SnapshotName)
}

// Segments returns a slice of Resource ID Segments which comprise this Snapshot ID
func (id SnapshotId) Segments() []resourceids.Segment {
	return []resourceids.Segment{
		resourceids.StaticSegment("staticSubscriptions", "subscriptions", "subscriptions"),
		resourceids.SubscriptionIdSegment("subscriptionId", "12345678-1234-9876-4563-123456789012"),
		resourceids.StaticSegment("staticResourceGroups", "resourceGroups", "resourceGroups"),
		resourceids.ResourceGroupSegment("resourceGroupName", "example-resource-group"),
		resourceids.StaticSegment("staticProviders", "providers", "providers"),
		resourceids.ResourceProviderSegment("staticMicrosoftNetApp", "Microsoft.NetApp", "Microsoft.NetApp"),
		resourceids.StaticSegment("staticNetAppAccounts", "netAppAccounts", "netAppAccounts"),
		resourceids.UserSpecifiedSegment("netAppAccountName", "netAppAccountValue"),
		resourceids.StaticSegment("staticCapacityPools", "capacityPools", "capacityPools"),
		resourceids.UserSpecifiedSegment("capacityPoolName", "capacityPoolValue"),
		resourceids.StaticSegment("staticVolumes", "volumes", "volumes"),
		resourceids.UserSpecifiedSegment("volumeName", "volumeValue"),
		resourceids.StaticSegment("staticSnapshots", "snapshots", "snapshots"),
		resourceids.UserSpecifiedSegment("snapshotName", "snapshotValue"),
	}
}

// String returns a human-readable description of this Snapshot ID
func (id SnapshotId) String() string {
	components := []string{
		fmt.Sprintf("Subscription: %q", id.SubscriptionId),
		fmt.Sprintf("Resource Group Name: %q", id.ResourceGroupName),
		fmt.Sprintf("Net App Account Name: %q", id.NetAppAccountName),
		fmt.Sprintf("Capacity Pool Name: %q", id.CapacityPoolName),
		fmt.Sprintf("Volume Name: %q", id.VolumeName),
		fmt.Sprintf("Snapshot Name: %q", id.SnapshotName),
	}
	return fmt.Sprintf("Snapshot (%s)", strings.Join(components, "\n"))
}
