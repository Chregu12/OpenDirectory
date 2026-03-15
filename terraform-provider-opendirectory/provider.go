package main

import (
	"context"
	"fmt"

	"github.com/Chregu12/terraform-provider-opendirectory/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider returns the OpenDirectory Terraform provider
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("OPENDIRECTORY_API_URL", nil),
				Description: "The URL of the OpenDirectory API (e.g., https://od.example.com)",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("OPENDIRECTORY_API_KEY", nil),
				Description: "API key for authentication with OpenDirectory",
			},
			"timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     30,
				Description: "HTTP request timeout in seconds",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"opendirectory_device":        resourceDevice(),
			"opendirectory_policy":        resourcePolicy(),
			"opendirectory_wifi_profile":  resourceWiFiProfile(),
			"opendirectory_vpn_profile":   resourceVPNProfile(),
			"opendirectory_update_policy": resourceUpdatePolicy(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"opendirectory_devices":           dataSourceDevices(),
			"opendirectory_compliance_status": dataSourceComplianceStatus(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	apiURL := d.Get("api_url").(string)
	apiKey := d.Get("api_key").(string)
	timeout := d.Get("timeout").(int)

	c := client.NewClient(apiURL, apiKey, timeout)

	return c, nil
}

// =====================================================
// Resource: opendirectory_device
// =====================================================

func resourceDevice() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceDeviceCreate,
		ReadContext:   resourceDeviceRead,
		UpdateContext: resourceDeviceUpdate,
		DeleteContext: resourceDeviceDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Device name",
			},
			"platform": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Device platform (windows, macos, linux)",
			},
			"owner": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Owner user ID",
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Device status",
			},
			"last_seen": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last seen timestamp",
			},
		},
	}
}

func resourceDeviceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	device := map[string]interface{}{
		"name":     d.Get("name").(string),
		"platform": d.Get("platform").(string),
	}
	if v, ok := d.GetOk("owner"); ok {
		device["owner"] = v.(string)
	}

	resp, err := c.Post("/api/devices", device)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating device: %s", err))
	}

	data := resp["data"].(map[string]interface{})
	d.SetId(data["id"].(string))

	return resourceDeviceRead(ctx, d, m)
}

func resourceDeviceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	resp, err := c.Get(fmt.Sprintf("/api/devices/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	data := resp["data"].(map[string]interface{})
	d.Set("name", data["name"])
	d.Set("platform", data["platform"])
	d.Set("status", data["status"])
	if v, ok := data["owner"]; ok {
		d.Set("owner", v)
	}
	if v, ok := data["lastSeen"]; ok {
		d.Set("last_seen", v)
	}

	return nil
}

func resourceDeviceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	device := map[string]interface{}{}
	if d.HasChange("name") {
		device["name"] = d.Get("name").(string)
	}
	if d.HasChange("owner") {
		device["owner"] = d.Get("owner").(string)
	}

	_, err := c.Put(fmt.Sprintf("/api/devices/%s", d.Id()), device)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceDeviceRead(ctx, d, m)
}

func resourceDeviceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	_, err := c.Delete(fmt.Sprintf("/api/devices/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

// =====================================================
// Resource: opendirectory_policy
// =====================================================

func resourcePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePolicyCreate,
		ReadContext:   resourcePolicyRead,
		UpdateContext: resourcePolicyUpdate,
		DeleteContext: resourcePolicyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Policy name",
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Policy type (security, compliance, update, network, encryption)",
			},
			"settings": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Policy settings",
			},
			"target_groups": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Target device groups",
			},
		},
	}
}

func resourcePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	policy := map[string]interface{}{
		"name": d.Get("name").(string),
		"type": d.Get("type").(string),
	}
	if v, ok := d.GetOk("settings"); ok {
		policy["settings"] = v
	}
	if v, ok := d.GetOk("target_groups"); ok {
		policy["targets"] = v
	}

	resp, err := c.Post("/api/policies", policy)
	if err != nil {
		return diag.FromErr(err)
	}

	data := resp["data"].(map[string]interface{})
	d.SetId(data["id"].(string))

	return resourcePolicyRead(ctx, d, m)
}

func resourcePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	resp, err := c.Get(fmt.Sprintf("/api/policies/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	data := resp["data"].(map[string]interface{})
	d.Set("name", data["name"])
	d.Set("type", data["type"])

	return nil
}

func resourcePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	policy := map[string]interface{}{
		"name": d.Get("name").(string),
		"type": d.Get("type").(string),
	}
	if v, ok := d.GetOk("settings"); ok {
		policy["settings"] = v
	}
	if v, ok := d.GetOk("target_groups"); ok {
		policy["targets"] = v
	}

	_, err := c.Put(fmt.Sprintf("/api/policies/%s", d.Id()), policy)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourcePolicyRead(ctx, d, m)
}

func resourcePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	_, err := c.Delete(fmt.Sprintf("/api/policies/%s", d.Id()))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

// =====================================================
// Resource: opendirectory_wifi_profile
// =====================================================

func resourceWiFiProfile() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceWiFiProfileCreate,
		ReadContext:   resourceWiFiProfileRead,
		UpdateContext: resourceWiFiProfileCreate, // re-deploy on update
		DeleteContext: resourceWiFiProfileDelete,
		Schema: map[string]*schema.Schema{
			"device_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Target device ID",
			},
			"ssid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "WiFi network SSID",
			},
			"security": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Security type (WPA2-Personal, WPA2-Enterprise, etc.)",
			},
			"eap_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "EAP type (TLS, TTLS, PEAP)",
			},
			"cert_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate ID for Enterprise security",
			},
			"auto_connect": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Auto-connect to this network",
			},
			"command_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Command ID from agent dispatch",
			},
		},
	}
}

func resourceWiFiProfileCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	profile := map[string]interface{}{
		"ssid":        d.Get("ssid").(string),
		"security":    d.Get("security").(string),
		"autoConnect": d.Get("auto_connect").(bool),
	}
	if v, ok := d.GetOk("eap_type"); ok {
		profile["eapType"] = v.(string)
	}
	if v, ok := d.GetOk("cert_id"); ok {
		profile["certId"] = v.(string)
	}

	resp, err := c.Post("/api/agent/network/configure-wifi", map[string]interface{}{
		"deviceId": d.Get("device_id").(string),
		"profile":  profile,
	})
	if err != nil {
		return diag.FromErr(err)
	}

	id := fmt.Sprintf("%s/%s", d.Get("device_id").(string), d.Get("ssid").(string))
	d.SetId(id)
	if cmdId, ok := resp["commandId"]; ok {
		d.Set("command_id", cmdId)
	}

	return nil
}

func resourceWiFiProfileRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// WiFi profiles are push-based; read is a no-op
	return nil
}

func resourceWiFiProfileDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	_, err := c.Post("/api/agent/network/remove-wifi", map[string]interface{}{
		"deviceId":  d.Get("device_id").(string),
		"profileId": d.Id(),
		"ssid":      d.Get("ssid").(string),
	})
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

// =====================================================
// Resource: opendirectory_vpn_profile
// =====================================================

func resourceVPNProfile() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVPNProfileCreate,
		ReadContext:   resourceVPNProfileRead,
		UpdateContext: resourceVPNProfileCreate,
		DeleteContext: resourceVPNProfileDelete,
		Schema: map[string]*schema.Schema{
			"device_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "VPN type (IKEv2, L2TP, OpenVPN, WireGuard)",
			},
			"server": {
				Type:     schema.TypeString,
				Required: true,
			},
			"command_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceVPNProfileCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	profile := map[string]interface{}{
		"name":   d.Get("name").(string),
		"type":   d.Get("type").(string),
		"server": d.Get("server").(string),
	}

	resp, err := c.Post("/api/agent/network/configure-vpn", map[string]interface{}{
		"deviceId": d.Get("device_id").(string),
		"profile":  profile,
	})
	if err != nil {
		return diag.FromErr(err)
	}

	id := fmt.Sprintf("%s/%s", d.Get("device_id").(string), d.Get("name").(string))
	d.SetId(id)
	if cmdId, ok := resp["commandId"]; ok {
		d.Set("command_id", cmdId)
	}

	return nil
}

func resourceVPNProfileRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceVPNProfileDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	_, err := c.Post("/api/agent/network/remove-vpn", map[string]interface{}{
		"deviceId":  d.Get("device_id").(string),
		"profileId": d.Id(),
	})
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")
	return nil
}

// =====================================================
// Resource: opendirectory_update_policy
// =====================================================

func resourceUpdatePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceUpdatePolicyCreate,
		ReadContext:   resourceUpdatePolicyRead,
		UpdateContext: resourceUpdatePolicyCreate,
		DeleteContext: resourceUpdatePolicyDelete,
		Schema: map[string]*schema.Schema{
			"device_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"auto_approve": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"maintenance_window": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Maintenance window (e.g., 'Sun 02:00-06:00')",
			},
			"reboot_policy": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "defer",
				Description: "Reboot policy: immediate, defer, user-choice",
			},
			"command_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceUpdatePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	policy := map[string]interface{}{
		"autoApprove":  d.Get("auto_approve").(bool),
		"rebootPolicy": d.Get("reboot_policy").(string),
	}
	if v, ok := d.GetOk("maintenance_window"); ok {
		policy["maintenanceWindow"] = v.(string)
	}

	resp, err := c.Post("/api/agent/update/configure", map[string]interface{}{
		"deviceId": d.Get("device_id").(string),
		"policy":   policy,
	})
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(d.Get("device_id").(string))
	if cmdId, ok := resp["commandId"]; ok {
		d.Set("command_id", cmdId)
	}

	return nil
}

func resourceUpdatePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceUpdatePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

// =====================================================
// Data Source: opendirectory_devices
// =====================================================

func dataSourceDevices() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceDevicesRead,
		Schema: map[string]*schema.Schema{
			"platform": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter by platform",
			},
			"status": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter by status",
			},
			"devices": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id":        {Type: schema.TypeString, Computed: true},
						"name":      {Type: schema.TypeString, Computed: true},
						"platform":  {Type: schema.TypeString, Computed: true},
						"status":    {Type: schema.TypeString, Computed: true},
						"owner":     {Type: schema.TypeString, Computed: true},
						"last_seen": {Type: schema.TypeString, Computed: true},
					},
				},
			},
		},
	}
}

func dataSourceDevicesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	resp, err := c.Get("/api/devices")
	if err != nil {
		return diag.FromErr(err)
	}

	devices := resp["data"].([]interface{})
	result := make([]map[string]interface{}, 0)

	platform := d.Get("platform").(string)
	status := d.Get("status").(string)

	for _, dev := range devices {
		device := dev.(map[string]interface{})
		if platform != "" && device["platform"] != platform {
			continue
		}
		if status != "" && device["status"] != status {
			continue
		}
		result = append(result, map[string]interface{}{
			"id":        device["id"],
			"name":      device["name"],
			"platform":  device["platform"],
			"status":    device["status"],
			"owner":     device["owner"],
			"last_seen": device["lastSeen"],
		})
	}

	d.SetId("opendirectory-devices")
	d.Set("devices", result)

	return nil
}

// =====================================================
// Data Source: opendirectory_compliance_status
// =====================================================

func dataSourceComplianceStatus() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceComplianceStatusRead,
		Schema: map[string]*schema.Schema{
			"overall_score": {
				Type:     schema.TypeFloat,
				Computed: true,
			},
			"compliant_devices": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"non_compliant_devices": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"active_threats": {
				Type:     schema.TypeInt,
				Computed: true,
			},
		},
	}
}

func dataSourceComplianceStatusRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := m.(*client.Client)

	resp, err := c.Get("/api/dashboard")
	if err != nil {
		return diag.FromErr(err)
	}

	data := resp["data"].(map[string]interface{})

	if compliance, ok := data["compliance"].(map[string]interface{}); ok {
		d.Set("overall_score", compliance["overallScore"])
		d.Set("compliant_devices", compliance["compliantDevices"])
		d.Set("non_compliant_devices", compliance["nonCompliantDevices"])
	}
	if threats, ok := data["threats"].(map[string]interface{}); ok {
		d.Set("active_threats", threats["active"])
	}

	d.SetId("opendirectory-compliance")
	return nil
}
