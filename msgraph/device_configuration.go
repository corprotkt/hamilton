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

type DeviceConfigurationClient struct {
	BaseClient Client
}

// Create a named Windows 10 General Configuration with the ODataType
// field suitably prepared.
func NewWindows10GeneralConfiguration(displayName *string) *Windows10GeneralConfiguration {
	config := &Windows10GeneralConfiguration{}

	if displayName != nil {
		config.DisplayName = displayName
	}
	config.ODataType = utils.StringPtr(odata.TypeWindows10GeneralConfiguration)

	return config
}

// Create a named AOSP Device Configuration (Android) with the ODataType
// field suitably prepared.
func NewAospDeviceOwnerDeviceConfiguration(displayName *string) *AospDeviceOwnerDeviceConfiguration {
	config := &AospDeviceOwnerDeviceConfiguration{}

	if displayName != nil {
		config.DisplayName = displayName
	}
	config.ODataType = utils.StringPtr(odata.TypeAospDeviceOwnerDeviceConfiguration)

	return config
}

// NewDeviceConfigurationClient returns a new DeviceConfigurationClient.
func NewDeviceConfigurationClient(tenantId string) *DeviceConfigurationClient {
	return &DeviceConfigurationClient{
		BaseClient: NewClient(VersionBeta, tenantId),
	}
}

// List returns a list of DeviceConfigurations, optionally queried using OData.
func (c *DeviceConfigurationClient) List(ctx context.Context, query odata.Query) (*[]DeviceConfiguration, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		DisablePaging:    query.Top > 0,
		OData:            query,
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity:      "/deviceManagement/deviceConfigurations",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		RawConfigurations *[]json.RawMessage `json:"value"`
	}

	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	var result []DeviceConfiguration

	// Device Compliance Policies come in many flavours, loop over the unmarshalled
	// result to massage those into the appropriate structs.

	if data.RawConfigurations != nil {
		for _, raw := range *data.RawConfigurations {
			var o odata.OData
			if err := json.Unmarshal(raw, &o); err != nil {
				return nil, status, fmt.Errorf("json.Unmarshall(): %v", err)
			}

			if o.Type != nil {
				switch *o.Type {
				case odata.TypeWindows10GeneralConfiguration:
					var configuration Windows10GeneralConfiguration
					if err := json.Unmarshal(raw, &configuration); err != nil {
						return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
					}
					result = append(result, configuration)
				case odata.TypeAospDeviceOwnerDeviceConfiguration:
					var configuration AospDeviceOwnerDeviceConfiguration
					if err := json.Unmarshal(raw, &configuration); err != nil {
						return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
					}
					result = append(result, configuration)
				}
			}
		}
	}

	return &result, status, nil
}

// Create a Windows10 General Configuration
func (c *DeviceConfigurationClient) CreateWindows10GeneralConfiguration(ctx context.Context,
	config *Windows10GeneralConfiguration) (*Windows10GeneralConfiguration, int, error) {
	var status int

	body, err := json.Marshal(config)
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
			Entity:      "/deviceManagement/deviceConfigurations",
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.Post(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newConfiguration Windows10GeneralConfiguration
	if err := json.Unmarshal(respBody, &newConfiguration); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newConfiguration, status, nil
}

// Get retrieves a device configuration.
func (c *DeviceConfigurationClient) Get(ctx context.Context, id string, query odata.Query) (DeviceConfiguration, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceConfigurations/%s", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("DeviceConfigurationClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var raw_config map[string]interface{}
	var config DeviceConfiguration

	if err := json.Unmarshal(respBody, &raw_config); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	} else {
		switch raw_config["@odata.type"] {
		case odata.TypeWindows10GeneralConfiguration:
			var win10_config Windows10GeneralConfiguration
			json.Unmarshal(respBody, &win10_config)
			config = win10_config
		case odata.TypeAospDeviceOwnerDeviceConfiguration:
			var aosp_config AospDeviceOwnerDeviceConfiguration
			json.Unmarshal(respBody, &aosp_config)
			config = aosp_config
		}

		return config, status, nil
	}
}

// Update amends an existing Configuration
func (c *DeviceConfigurationClient) Update(ctx context.Context, config DeviceConfiguration) (int, error) {
	var status int

	id := config.GetConfigurationBase().ID
	if id == nil {
		return status, fmt.Errorf("DeviceConfigurationClient.Update(): cannot update device configuration with nil ID")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return status, fmt.Errorf("json.Marshal(): %v", err)
	}

	_, status, _, err = c.BaseClient.Patch(ctx, PatchHttpRequestInput{
		Body:             body,
		ValidStatusCodes: []int{http.StatusNoContent},
		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceConfigurations/%s", *id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return status, fmt.Errorf("DeviceConfigurationClient.BaseClient.Patch(): %v", err)
	}

	return status, nil
}

func (c *DeviceConfigurationClient) Delete(ctx context.Context, id string) (int, error) {
	_, status, _, err := c.BaseClient.Delete(ctx, DeleteHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,

		ValidStatusCodes: []int{http.StatusNoContent, http.StatusOK},

		Uri: Uri{
			Entity:      fmt.Sprintf("/deviceManagement/deviceConfigurations/%s", id),
			HasTenantId: true,
		},
	})
	if err != nil {
		return status, fmt.Errorf("DeviceConfigurationClient.BaseClient.Delete(): %v", err)
	}

	return status, nil
}

func (c *DeviceConfigurationClient) AddAssignments(ctx context.Context, id string, assignments []DeviceCompliancePolicyAssignment) (int, error) {
	return c.BaseClient.AddAssignments(ctx, "/deviceManagement/deviceConfigurations", id, assignments)
}

func (c *DeviceConfigurationClient) ListAssignments(ctx context.Context, id string, query odata.Query) (*[]DeviceCompliancePolicyAssignment, int, error) {
	return c.BaseClient.ListAssignments(ctx, "/deviceManagement/deviceConfigurations", id, query)
}
