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

func (c *Client) ListAssignments(ctx context.Context, prefix string, id string, query odata.Query) (*[]DeviceCompliancePolicyAssignment, int, error) {
	resp, status, _, err := c.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("%s/%s/assignments", prefix, id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("BaseClient.Get(): %v", err)
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

func (c *Client) AddAssignments(ctx context.Context, prefix string, id string, assignments []DeviceCompliancePolicyAssignment) (int, error) {
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
	_, status, _, err = c.Post(ctx, PostHttpRequestInput{
		Body: body,
		OData: odata.Query{
			Metadata: odata.MetadataFull,
		},
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("%s/%s/assign", prefix, id),
			HasTenantId: true,
		},
	})

	if err != nil {
		return status, fmt.Errorf("Client.Post(): %v", err)
	}

	return status, nil
}
