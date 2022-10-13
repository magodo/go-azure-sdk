package replicationrecoveryplans

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

var _ resourceids.ResourceId = ReplicationRecoveryPlanId{}

// ReplicationRecoveryPlanId is a struct representing the Resource ID for a Replication Recovery Plan
type ReplicationRecoveryPlanId struct {
	SubscriptionId    string
	ResourceGroupName string
	ResourceName      string
	RecoveryPlanName  string
}

// NewReplicationRecoveryPlanID returns a new ReplicationRecoveryPlanId struct
func NewReplicationRecoveryPlanID(subscriptionId string, resourceGroupName string, resourceName string, recoveryPlanName string) ReplicationRecoveryPlanId {
	return ReplicationRecoveryPlanId{
		SubscriptionId:    subscriptionId,
		ResourceGroupName: resourceGroupName,
		ResourceName:      resourceName,
		RecoveryPlanName:  recoveryPlanName,
	}
}

// ParseReplicationRecoveryPlanID parses 'input' into a ReplicationRecoveryPlanId
func ParseReplicationRecoveryPlanID(input string) (*ReplicationRecoveryPlanId, error) {
	parser := resourceids.NewParserFromResourceIdType(ReplicationRecoveryPlanId{})
	parsed, err := parser.Parse(input, false)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := ReplicationRecoveryPlanId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, fmt.Errorf("the segment 'subscriptionId' was not found in the resource id %q", input)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceGroupName' was not found in the resource id %q", input)
	}

	if id.ResourceName, ok = parsed.Parsed["resourceName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceName' was not found in the resource id %q", input)
	}

	if id.RecoveryPlanName, ok = parsed.Parsed["recoveryPlanName"]; !ok {
		return nil, fmt.Errorf("the segment 'recoveryPlanName' was not found in the resource id %q", input)
	}

	return &id, nil
}

// ParseReplicationRecoveryPlanIDInsensitively parses 'input' case-insensitively into a ReplicationRecoveryPlanId
// note: this method should only be used for API response data and not user input
func ParseReplicationRecoveryPlanIDInsensitively(input string) (*ReplicationRecoveryPlanId, error) {
	parser := resourceids.NewParserFromResourceIdType(ReplicationRecoveryPlanId{})
	parsed, err := parser.Parse(input, true)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := ReplicationRecoveryPlanId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, fmt.Errorf("the segment 'subscriptionId' was not found in the resource id %q", input)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceGroupName' was not found in the resource id %q", input)
	}

	if id.ResourceName, ok = parsed.Parsed["resourceName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceName' was not found in the resource id %q", input)
	}

	if id.RecoveryPlanName, ok = parsed.Parsed["recoveryPlanName"]; !ok {
		return nil, fmt.Errorf("the segment 'recoveryPlanName' was not found in the resource id %q", input)
	}

	return &id, nil
}

// ValidateReplicationRecoveryPlanID checks that 'input' can be parsed as a Replication Recovery Plan ID
func ValidateReplicationRecoveryPlanID(input interface{}, key string) (warnings []string, errors []error) {
	v, ok := input.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected %q to be a string", key))
		return
	}

	if _, err := ParseReplicationRecoveryPlanID(v); err != nil {
		errors = append(errors, err)
	}

	return
}

// ID returns the formatted Replication Recovery Plan ID
func (id ReplicationRecoveryPlanId) ID() string {
	fmtString := "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.RecoveryServices/vaults/%s/replicationRecoveryPlans/%s"
	return fmt.Sprintf(fmtString, id.SubscriptionId, id.ResourceGroupName, id.ResourceName, id.RecoveryPlanName)
}

// Segments returns a slice of Resource ID Segments which comprise this Replication Recovery Plan ID
func (id ReplicationRecoveryPlanId) Segments() []resourceids.Segment {
	return []resourceids.Segment{
		resourceids.StaticSegment("staticSubscriptions", "subscriptions", "subscriptions"),
		resourceids.SubscriptionIdSegment("subscriptionId", "12345678-1234-9876-4563-123456789012"),
		resourceids.StaticSegment("staticResourceGroups", "resourceGroups", "resourceGroups"),
		resourceids.ResourceGroupSegment("resourceGroupName", "example-resource-group"),
		resourceids.StaticSegment("staticProviders", "providers", "providers"),
		resourceids.ResourceProviderSegment("staticMicrosoftRecoveryServices", "Microsoft.RecoveryServices", "Microsoft.RecoveryServices"),
		resourceids.StaticSegment("staticVaults", "vaults", "vaults"),
		resourceids.UserSpecifiedSegment("resourceName", "resourceValue"),
		resourceids.StaticSegment("staticReplicationRecoveryPlans", "replicationRecoveryPlans", "replicationRecoveryPlans"),
		resourceids.UserSpecifiedSegment("recoveryPlanName", "recoveryPlanValue"),
	}
}

// String returns a human-readable description of this Replication Recovery Plan ID
func (id ReplicationRecoveryPlanId) String() string {
	components := []string{
		fmt.Sprintf("Subscription: %q", id.SubscriptionId),
		fmt.Sprintf("Resource Group Name: %q", id.ResourceGroupName),
		fmt.Sprintf("Resource Name: %q", id.ResourceName),
		fmt.Sprintf("Recovery Plan Name: %q", id.RecoveryPlanName),
	}
	return fmt.Sprintf("Replication Recovery Plan (%s)", strings.Join(components, "\n"))
}
