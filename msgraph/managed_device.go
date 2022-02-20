package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/manicminer/hamilton/odata"
)

type ManagedDeviceClient struct {
	BaseClient Client
}

// NewManagedDeviceClient returns a new ManagedDevicesClient.
func NewManagedDeviceClient(tenantId string) *ManagedDeviceClient {
	return &ManagedDeviceClient{
		BaseClient: NewClient(VersionBeta, tenantId),
	}
}

// List returns a list of ManagedDevices, optionally queried using OData.
func (c *ManagedDeviceClient) List(ctx context.Context, query odata.Query) (*[]ManagedDevice, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		DisablePaging:    query.Top > 0,
		OData:            query,
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity:      "/deviceManagement/managedDevices",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("ManagedDevicesClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		ManagedDevices []ManagedDevice `json:"value"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &data.ManagedDevices, status, nil
}

// GetWindowsProtectionState returns the protection state of the machine, optionally queried using OData.
func (c *ManagedDeviceClient) GetWindowsProtectionState(ctx context.Context, id string, query odata.Query) (*WindowsProtectionState, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		DisablePaging:          query.Top > 0,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/managedDevices/%s/windowsProtectionState", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("ManagedDeviceClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data WindowsProtectionState

	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &data, status, nil
}

// Action: force an Intune synchronization
func (c *ManagedDeviceClient) Sync(ctx context.Context, id string) (int, error) {
	_, status, _, err := c.BaseClient.Post(ctx, PostHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusNoContent},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/managedDevices/%s/syncDevice", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return status, fmt.Errorf("ManagedDeviceClient.BaseClient.Post(): %v", err)
	}

	return status, nil
}
