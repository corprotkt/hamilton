package msgraph_test

import (
	"testing"

	"github.com/manicminer/hamilton/internal/test"
	"github.com/manicminer/hamilton/odata"
)

// Test ManagedDevices. As one cannot create one ManagedDevice programmatically
// it only tests getting the list of those.
func TestManagedDevice(t *testing.T) {
	c := test.NewTest(t)
	defer c.CancelFunc()

	testManagedDeviceList(t, c)
	testManagedDevicesWindowsProtectionState(t, c)
}

func testManagedDeviceList(t *testing.T, c *test.Test) {
	managed_devices, _, err := c.ManagedDeviceClient.List(c.Context, odata.Query{})
	if err != nil {
		t.Fatalf("ManagedDeviceClient.List(): %v", err)
	}
	if managed_devices == nil {
		t.Fatal("ManagedDeviceClient.List(): managed_devices was nil")
	} else {
		for _, device := range *managed_devices {
			t.Logf("Device: %+v\n", device)
		}
	}
}

func testManagedDevicesWindowsProtectionState(t *testing.T, c *test.Test) {
	managed_devices, _, err := c.ManagedDeviceClient.List(c.Context, odata.Query{})
	if err != nil {
		t.Fatalf("ManagedDeviceClient.List(): %v", err)
	}
	if managed_devices == nil {
		t.Fatal("ManagedDeviceClient.List(): managed_devices was nil")
	}

	t.Logf("n=%d\n", len(*managed_devices))

	for _, device := range *managed_devices {
		state, _, err := c.ManagedDeviceClient.GetWindowsProtectionState(c.Context, *device.ID, odata.Query{})

		if err != nil {
			t.Fatalf("ManagedDeviceClient.GetWindowsProtectionState(%s): %v", *device.ID, err)
		}
		if state == nil {
			t.Fatalf("ManagedDeviceClient.GetWindowsProtectionState(%s): state was nil", *device.ID)
		}

		t.Logf("%s %v\n", *device.ID, *device.ComplianceState)

	}
}
