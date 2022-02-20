package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/manicminer/hamilton/internal/utils"
	"github.com/manicminer/hamilton/odata"
)

type DeviceCompliancePolicyClient struct {
	BaseClient Client
}

// NewCompliancePolicyClient returns a new CompliancePolicyClient.
func NewDeviceCompliancePolicyClient(tenantId string) *DeviceCompliancePolicyClient {
	return &DeviceCompliancePolicyClient{
		BaseClient: NewClient(VersionBeta, tenantId),
	}
}

// List returns a list of DeviceCompliancePolicies, optionally queried using OData.
func (c *DeviceCompliancePolicyClient) List(ctx context.Context, query odata.Query) (*[]DeviceCompliancePolicy, int, error) {

	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		DisablePaging:    query.Top > 0,
		OData:            query,
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity:      "/deviceManagement/deviceCompliancePolicies",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("CompliancePolicyClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		RawPolicies *[]json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	var result []DeviceCompliancePolicy

	// Device Compliance Policies come in many flavours, loop over the unmarshalled
	// result to massage those into the appropriate structs.

	if data.RawPolicies != nil {
		for _, raw := range *data.RawPolicies {
			var o odata.OData
			if err := json.Unmarshal(raw, &o); err != nil {
				return nil, status, fmt.Errorf("json.Unmarshall(): %v", err)
			}

			if o.Type != nil {
				switch *o.Type {
				case odata.TypeDeviceCompliancePolicyWindows10:
					var policy Windows10DeviceCompliancePolicy
					if err := json.Unmarshal(raw, &policy); err != nil {
						return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
					}
					result = append(result, policy)
				case odata.TypeDeviceCompliancePolicyIOS:
					var policy IOSDeviceCompliancePolicy
					if err := json.Unmarshal(raw, &policy); err != nil {
						return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
					}
					result = append(result, policy)
				}
			}
		}
	}

	return &result, status, nil
}

// Create a named Windows 10 Compliance Policy with the ODataType
// field suitably prepared.
func NewWindows10CompliancePolicy(displayName *string) *Windows10DeviceCompliancePolicy {
	policy := &Windows10DeviceCompliancePolicy{}

	if displayName != nil {
		policy.DisplayName = displayName
	}
	policy.ODataType = utils.StringPtr(odata.TypeDeviceCompliancePolicyWindows10)

	return policy
}

// Create a named iOS Compliance Policy with the ODataType
// field suitably prepared.
func NewIOSCompliancePolicy(displayName *string) *IOSDeviceCompliancePolicy {
	policy := &IOSDeviceCompliancePolicy{}

	if displayName != nil {
		policy.DisplayName = displayName
	}
	policy.ODataType = utils.StringPtr(odata.TypeDeviceCompliancePolicyIOS)

	return policy
}

// Create a Windows10 Compliance Policy
func (c *DeviceCompliancePolicyClient) CreateWindows10CompliancePolicy(ctx context.Context,
	policy *Windows10DeviceCompliancePolicy) (*Windows10DeviceCompliancePolicy, int, error) {
	var status int

	body, err := json.Marshal(policy)
	if err != nil {
		return nil, status, fmt.Errorf("json.Marshal(): %v", err)
	}

	resp, status, _, err := c.BaseClient.Post(ctx, PostHttpRequestInput{
		Body: body,
		OData: odata.Query{
			Metadata: odata.MetadataFull,
		},
		ValidStatusCodes: []int{http.StatusCreated},
		Uri: Uri{
			Entity:      "/deviceManagement/deviceCompliancePolicies",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Post(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newPolicy Windows10DeviceCompliancePolicy
	if err := json.Unmarshal(respBody, &newPolicy); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newPolicy, status, nil
}

// Create a IOS Compliance Policy
func (c *DeviceCompliancePolicyClient) CreateIOSCompliancePolicy(ctx context.Context,
	policy *IOSDeviceCompliancePolicy) (*IOSDeviceCompliancePolicy, int, error) {
	var status int

	body, err := json.Marshal(policy)
	if err != nil {
		return nil, status, fmt.Errorf("json.Marshal(): %v", err)
	}

	resp, status, _, err := c.BaseClient.Post(ctx, PostHttpRequestInput{
		Body: body,
		OData: odata.Query{
			Metadata: odata.MetadataFull,
		},
		ValidStatusCodes: []int{http.StatusCreated},
		Uri: Uri{
			Entity:      "/deviceManagement/deviceCompliancePolicies",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Post(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newPolicy IOSDeviceCompliancePolicy
	if err := json.Unmarshal(respBody, &newPolicy); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newPolicy, status, nil
}

// Get retrieves a device compliance policy.
func (c *DeviceCompliancePolicyClient) Get(ctx context.Context, id string, query odata.Query) (DeviceCompliancePolicy, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceCompliancePolicies/%s", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var raw_policy map[string]interface{}
	var policy DeviceCompliancePolicy

	if err := json.Unmarshal(respBody, &raw_policy); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	} else {
		switch raw_policy["@odata.type"] {
		case odata.TypeDeviceCompliancePolicyWindows10:
			var win10_policy Windows10DeviceCompliancePolicy
			json.Unmarshal(respBody, &win10_policy)
			policy = win10_policy
		case odata.TypeDeviceCompliancePolicyIOS:
			var ios_policy IOSDeviceCompliancePolicy
			json.Unmarshal(respBody, &ios_policy)
			policy = ios_policy
		}

		return policy, status, nil
	}
}

func (c *DeviceCompliancePolicyClient) Delete(ctx context.Context, id string) (int, error) {
	_, status, _, err := c.BaseClient.Delete(ctx, DeleteHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,

		// Documentation says that a successful DELETE is supposed to return
		// http.StatusNoContent (204) but it actually returns http.StatusOK (200)…
		ValidStatusCodes: []int{http.StatusNoContent, http.StatusOK},

		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceCompliancePolicies/%s", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Delete(): %v", err)
	}

	return status, nil
}

// Update amends an existing Policy
func (c *DeviceCompliancePolicyClient) Update(ctx context.Context, policy DeviceCompliancePolicy) (int, error) {
	var status int

	id := policy.GetPolicyBase().ID
	if id == nil {
		return status, fmt.Errorf("DeviceCompliancePolicyClient.Update(): cannot update device compliance policy with nil ID")
	}

	body, err := json.Marshal(policy)
	if err != nil {
		return status, fmt.Errorf("json.Marshal(): %v", err)
	}

	_, status, _, err = c.BaseClient.Patch(ctx, PatchHttpRequestInput{
		Body:             body,
		ValidStatusCodes: []int{http.StatusNoContent},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceCompliancePolicies/%s", *id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Patch(): %v", err)
	}

	return status, nil
}

func (c *DeviceCompliancePolicyClient) ListAssignments(ctx context.Context, id string, query odata.Query) (*[]DeviceCompliancePolicyAssignment, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceCompliancePolicies/%s/assignments", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		Assignments *[]DeviceCompliancePolicyAssignment `json:"value"`
	}

	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return data.Assignments, status, nil
}

func NewAllDevicesAssignmentTarget() *DeviceAndAppManagementAssignmentTargetAllDevices {
	target := &DeviceAndAppManagementAssignmentTargetAllDevices{}

	target.ODataType = utils.StringPtr(odata.TypeDeviceComplianceAssignmentTargetAllDevices)

	return target
}

func NewGroupAssignmentTarget(group *Group) *DeviceAndAppManagementAssignmentGroupAssignmentTarget {
	target := &DeviceAndAppManagementAssignmentGroupAssignmentTarget{GroupID: group.ID}

	target.ODataType = utils.StringPtr(odata.TypeDeviceComplianceAssignmentTargetGroup)

	return target
}

func (c *DeviceCompliancePolicyClient) AddAssignments(ctx context.Context, id string, assignments []DeviceCompliancePolicyAssignment) (int, error) {
	var status int

	type d struct {
		Assignments *[]DeviceCompliancePolicyAssignment `json:"assignments,omitempty"`
	}

	dd := d{&assignments}

	body, err := json.Marshal(dd)
	if err != nil {
		return status, fmt.Errorf("json.Marshal(): %v", err)
	}

	// Rather than the 'assignments' Navigation Property, one has to
	// use the 'assign' Action here, for reasons not yet fully clear
	// to me.
	_, status, _, err = c.BaseClient.Post(ctx, PostHttpRequestInput{
		Body: body,
		OData: odata.Query{
			Metadata: odata.MetadataFull,
		},
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceCompliancePolicies/%s/assign", id),
			HasTenantId: true,
		},
	})

	if err != nil {
		return status, fmt.Errorf("DeviceCompliancePolicyClient.BaseClient.Post(): %v", err)
	}

	return status, nil
}
