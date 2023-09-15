package tagproductlink

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ resourceids.ResourceId = ProductLinkId{}

// ProductLinkId is a struct representing the Resource ID for a Product Link
type ProductLinkId struct {
	SubscriptionId    string
	ResourceGroupName string
	ServiceName       string
	TagId             string
	ProductLinkId     string
}

// NewProductLinkID returns a new ProductLinkId struct
func NewProductLinkID(subscriptionId string, resourceGroupName string, serviceName string, tagId string, productLinkId string) ProductLinkId {
	return ProductLinkId{
		SubscriptionId:    subscriptionId,
		ResourceGroupName: resourceGroupName,
		ServiceName:       serviceName,
		TagId:             tagId,
		ProductLinkId:     productLinkId,
	}
}

// ParseProductLinkID parses 'input' into a ProductLinkId
func ParseProductLinkID(input string) (*ProductLinkId, error) {
	parser := resourceids.NewParserFromResourceIdType(ProductLinkId{})
	parsed, err := parser.Parse(input, false)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := ProductLinkId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "subscriptionId", *parsed)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "resourceGroupName", *parsed)
	}

	if id.ServiceName, ok = parsed.Parsed["serviceName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "serviceName", *parsed)
	}

	if id.TagId, ok = parsed.Parsed["tagId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "tagId", *parsed)
	}

	if id.ProductLinkId, ok = parsed.Parsed["productLinkId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "productLinkId", *parsed)
	}

	return &id, nil
}

// ParseProductLinkIDInsensitively parses 'input' case-insensitively into a ProductLinkId
// note: this method should only be used for API response data and not user input
func ParseProductLinkIDInsensitively(input string) (*ProductLinkId, error) {
	parser := resourceids.NewParserFromResourceIdType(ProductLinkId{})
	parsed, err := parser.Parse(input, true)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := ProductLinkId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "subscriptionId", *parsed)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "resourceGroupName", *parsed)
	}

	if id.ServiceName, ok = parsed.Parsed["serviceName"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "serviceName", *parsed)
	}

	if id.TagId, ok = parsed.Parsed["tagId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "tagId", *parsed)
	}

	if id.ProductLinkId, ok = parsed.Parsed["productLinkId"]; !ok {
		return nil, resourceids.NewSegmentNotSpecifiedError(id, "productLinkId", *parsed)
	}

	return &id, nil
}

// ValidateProductLinkID checks that 'input' can be parsed as a Product Link ID
func ValidateProductLinkID(input interface{}, key string) (warnings []string, errors []error) {
	v, ok := input.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected %q to be a string", key))
		return
	}

	if _, err := ParseProductLinkID(v); err != nil {
		errors = append(errors, err)
	}

	return
}

// ID returns the formatted Product Link ID
func (id ProductLinkId) ID() string {
	fmtString := "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/tags/%s/productLinks/%s"
	return fmt.Sprintf(fmtString, id.SubscriptionId, id.ResourceGroupName, id.ServiceName, id.TagId, id.ProductLinkId)
}

// Segments returns a slice of Resource ID Segments which comprise this Product Link ID
func (id ProductLinkId) Segments() []resourceids.Segment {
	return []resourceids.Segment{
		resourceids.StaticSegment("staticSubscriptions", "subscriptions", "subscriptions"),
		resourceids.SubscriptionIdSegment("subscriptionId", "12345678-1234-9876-4563-123456789012"),
		resourceids.StaticSegment("staticResourceGroups", "resourceGroups", "resourceGroups"),
		resourceids.ResourceGroupSegment("resourceGroupName", "example-resource-group"),
		resourceids.StaticSegment("staticProviders", "providers", "providers"),
		resourceids.ResourceProviderSegment("staticMicrosoftApiManagement", "Microsoft.ApiManagement", "Microsoft.ApiManagement"),
		resourceids.StaticSegment("staticService", "service", "service"),
		resourceids.UserSpecifiedSegment("serviceName", "serviceValue"),
		resourceids.StaticSegment("staticTags", "tags", "tags"),
		resourceids.UserSpecifiedSegment("tagId", "tagIdValue"),
		resourceids.StaticSegment("staticProductLinks", "productLinks", "productLinks"),
		resourceids.UserSpecifiedSegment("productLinkId", "productLinkIdValue"),
	}
}

// String returns a human-readable description of this Product Link ID
func (id ProductLinkId) String() string {
	components := []string{
		fmt.Sprintf("Subscription: %q", id.SubscriptionId),
		fmt.Sprintf("Resource Group Name: %q", id.ResourceGroupName),
		fmt.Sprintf("Service Name: %q", id.ServiceName),
		fmt.Sprintf("Tag: %q", id.TagId),
		fmt.Sprintf("Product Link: %q", id.ProductLinkId),
	}
	return fmt.Sprintf("Product Link (%s)", strings.Join(components, "\n"))
}
