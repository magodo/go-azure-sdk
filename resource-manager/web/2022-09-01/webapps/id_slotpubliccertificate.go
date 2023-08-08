package webapps

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ resourceids.ResourceId = SlotPublicCertificateId{}

// SlotPublicCertificateId is a struct representing the Resource ID for a Slot Public Certificate
type SlotPublicCertificateId struct {
	SubscriptionId        string
	ResourceGroupName     string
	SiteName              string
	SlotName              string
	PublicCertificateName string
}

// NewSlotPublicCertificateID returns a new SlotPublicCertificateId struct
func NewSlotPublicCertificateID(subscriptionId string, resourceGroupName string, siteName string, slotName string, publicCertificateName string) SlotPublicCertificateId {
	return SlotPublicCertificateId{
		SubscriptionId:        subscriptionId,
		ResourceGroupName:     resourceGroupName,
		SiteName:              siteName,
		SlotName:              slotName,
		PublicCertificateName: publicCertificateName,
	}
}

// ParseSlotPublicCertificateID parses 'input' into a SlotPublicCertificateId
func ParseSlotPublicCertificateID(input string) (*SlotPublicCertificateId, error) {
	parser := resourceids.NewParserFromResourceIdType(SlotPublicCertificateId{})
	parsed, err := parser.Parse(input, false)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := SlotPublicCertificateId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "subscriptionId", *parsed)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "resourceGroupName", *parsed)
	}

	if id.SiteName, ok = parsed.Parsed["siteName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "siteName", *parsed)
	}

	if id.SlotName, ok = parsed.Parsed["slotName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "slotName", *parsed)
	}

	if id.PublicCertificateName, ok = parsed.Parsed["publicCertificateName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "publicCertificateName", *parsed)
	}

	return &id, nil
}

// ParseSlotPublicCertificateIDInsensitively parses 'input' case-insensitively into a SlotPublicCertificateId
// note: this method should only be used for API response data and not user input
func ParseSlotPublicCertificateIDInsensitively(input string) (*SlotPublicCertificateId, error) {
	parser := resourceids.NewParserFromResourceIdType(SlotPublicCertificateId{})
	parsed, err := parser.Parse(input, true)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := SlotPublicCertificateId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "subscriptionId", *parsed)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "resourceGroupName", *parsed)
	}

	if id.SiteName, ok = parsed.Parsed["siteName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "siteName", *parsed)
	}

	if id.SlotName, ok = parsed.Parsed["slotName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "slotName", *parsed)
	}

	if id.PublicCertificateName, ok = parsed.Parsed["publicCertificateName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "publicCertificateName", *parsed)
	}

	return &id, nil
}

// ValidateSlotPublicCertificateID checks that 'input' can be parsed as a Slot Public Certificate ID
func ValidateSlotPublicCertificateID(input interface{}, key string) (warnings []string, errors []error) {
	v, ok := input.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected %q to be a string", key))
		return
	}

	if _, err := ParseSlotPublicCertificateID(v); err != nil {
		errors = append(errors, err)
	}

	return
}

// ID returns the formatted Slot Public Certificate ID
func (id SlotPublicCertificateId) ID() string {
	fmtString := "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/slots/%s/publicCertificates/%s"
	return fmt.Sprintf(fmtString, id.SubscriptionId, id.ResourceGroupName, id.SiteName, id.SlotName, id.PublicCertificateName)
}

// Segments returns a slice of Resource ID Segments which comprise this Slot Public Certificate ID
func (id SlotPublicCertificateId) Segments() []resourceids.Segment {
	return []resourceids.Segment{
		resourceids.StaticSegment("staticSubscriptions", "subscriptions", "subscriptions"),
		resourceids.SubscriptionIdSegment("subscriptionId", "12345678-1234-9876-4563-123456789012"),
		resourceids.StaticSegment("staticResourceGroups", "resourceGroups", "resourceGroups"),
		resourceids.ResourceGroupSegment("resourceGroupName", "example-resource-group"),
		resourceids.StaticSegment("staticProviders", "providers", "providers"),
		resourceids.ResourceProviderSegment("staticMicrosoftWeb", "Microsoft.Web", "Microsoft.Web"),
		resourceids.StaticSegment("staticSites", "sites", "sites"),
		resourceids.UserSpecifiedSegment("siteName", "siteValue"),
		resourceids.StaticSegment("staticSlots", "slots", "slots"),
		resourceids.UserSpecifiedSegment("slotName", "slotValue"),
		resourceids.StaticSegment("staticPublicCertificates", "publicCertificates", "publicCertificates"),
		resourceids.UserSpecifiedSegment("publicCertificateName", "publicCertificateValue"),
	}
}

// String returns a human-readable description of this Slot Public Certificate ID
func (id SlotPublicCertificateId) String() string {
	components := []string{
		fmt.Sprintf("Subscription: %q", id.SubscriptionId),
		fmt.Sprintf("Resource Group Name: %q", id.ResourceGroupName),
		fmt.Sprintf("Site Name: %q", id.SiteName),
		fmt.Sprintf("Slot Name: %q", id.SlotName),
		fmt.Sprintf("Public Certificate Name: %q", id.PublicCertificateName),
	}
	return fmt.Sprintf("Slot Public Certificate (%s)", strings.Join(components, "\n"))
}
