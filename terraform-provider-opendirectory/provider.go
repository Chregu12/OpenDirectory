package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/opendirectory/terraform-provider-opendirectory/client"
)

// Provider returns the OpenDirectory Terraform provider.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("OPENDIRECTORY_API_URL", nil),
				Description: "The base URL of the OpenDirectory API (e.g. https://od.example.com).",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("OPENDIRECTORY_API_KEY", nil),
				Description: "API key for authenticating with the OpenDirectory API.",
			},
			"timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     30,
				Description: "HTTP request timeout in seconds.",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"opendirectory_device":        resourceDevice(),
			"opendirectory_user":          resourceUser(),
			"opendirectory_group":         resourceGroup(),
			"opendirectory_policy":        resourcePolicy(),
			"opendirectory_wifi_profile":  resourceWiFiProfile(),
			"opendirectory_vpn_profile":   resourceVPNProfile(),
			"opendirectory_update_policy": resourceUpdatePolicy(),
			"opendirectory_certificate":   resourceCertificate(),
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

	var diags diag.Diagnostics

	if apiURL == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Missing API URL",
			Detail:   "The api_url must be set in the provider configuration or via OPENDIRECTORY_API_URL.",
		})
	}
	if apiKey == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Missing API Key",
			Detail:   "The api_key must be set in the provider configuration or via OPENDIRECTORY_API_KEY.",
		})
	}
	if diags.HasError() {
		return nil, diags
	}

	c := client.NewClient(apiURL, apiKey, timeout)
	return c, diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_device
// ──────────────────────────────────────────────────────────────────────────────

func resourceDevice() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a device in OpenDirectory.",
		CreateContext: resourceDeviceCreate,
		ReadContext:   resourceDeviceRead,
		UpdateContext: resourceDeviceUpdate,
		DeleteContext: resourceDeviceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name of the device.",
			},
			"hostname": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Hostname of the device.",
			},
			"platform": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Operating system platform (windows, macos, linux).",
			},
			"os_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Operating system version.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Hardware serial number.",
			},
			"model": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Device model.",
			},
			"status": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Device status (active, inactive, pending).",
			},
			"owner": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User ID of the device owner.",
			},
			"group_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group ID the device belongs to.",
			},
			"tags": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Tags for the device.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"enrolled_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the device was enrolled.",
			},
			"last_seen_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp of last device check-in.",
			},
			"compliance_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current compliance status of the device.",
			},
		},
	}
}

func resourceDeviceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	device := &client.Device{
		Name:         d.Get("name").(string),
		Platform:     d.Get("platform").(string),
		Hostname:     d.Get("hostname").(string),
		OSVersion:    d.Get("os_version").(string),
		SerialNumber: d.Get("serial_number").(string),
		Model:        d.Get("model").(string),
		Status:       d.Get("status").(string),
		Owner:        d.Get("owner").(string),
		GroupID:      d.Get("group_id").(string),
	}
	if v, ok := d.GetOk("tags"); ok {
		for _, tag := range v.([]interface{}) {
			device.Tags = append(device.Tags, tag.(string))
		}
	}

	created, err := c.CreateDevice(device)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating device: %w", err))
	}

	d.SetId(created.ID)
	return resourceDeviceRead(ctx, d, meta)
}

func resourceDeviceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	device, err := c.GetDevice(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading device %s: %w", d.Id(), err))
	}

	d.Set("name", device.Name)
	d.Set("hostname", device.Hostname)
	d.Set("platform", device.Platform)
	d.Set("os_version", device.OSVersion)
	d.Set("serial_number", device.SerialNumber)
	d.Set("model", device.Model)
	d.Set("status", device.Status)
	d.Set("owner", device.Owner)
	d.Set("group_id", device.GroupID)
	d.Set("tags", device.Tags)
	d.Set("enrolled_at", device.EnrolledAt)
	d.Set("last_seen_at", device.LastSeenAt)
	d.Set("compliance_status", device.ComplianceStatus)

	return diags
}

func resourceDeviceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	device := &client.Device{
		Name:         d.Get("name").(string),
		Platform:     d.Get("platform").(string),
		Hostname:     d.Get("hostname").(string),
		OSVersion:    d.Get("os_version").(string),
		SerialNumber: d.Get("serial_number").(string),
		Model:        d.Get("model").(string),
		Status:       d.Get("status").(string),
		Owner:        d.Get("owner").(string),
		GroupID:      d.Get("group_id").(string),
	}
	if v, ok := d.GetOk("tags"); ok {
		for _, tag := range v.([]interface{}) {
			device.Tags = append(device.Tags, tag.(string))
		}
	}

	_, err := c.UpdateDevice(d.Id(), device)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating device %s: %w", d.Id(), err))
	}

	return resourceDeviceRead(ctx, d, meta)
}

func resourceDeviceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	err := c.DeleteDevice(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting device %s: %w", d.Id(), err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_user
// ──────────────────────────────────────────────────────────────────────────────

func resourceUser() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a user in OpenDirectory.",
		CreateContext: resourceUserCreate,
		ReadContext:   resourceUserRead,
		UpdateContext: resourceUserUpdate,
		DeleteContext: resourceUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique username.",
			},
			"email": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "User email address.",
			},
			"full_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Full display name.",
			},
			"role": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "user",
				Description: "User role (admin, user, auditor).",
			},
			"status": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "User status (active, suspended, pending).",
			},
			"group_ids": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of group IDs the user belongs to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the user was created.",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp of last update.",
			},
		},
	}
}

func resourceUserCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	user := &client.User{
		Username: d.Get("username").(string),
		Email:    d.Get("email").(string),
		FullName: d.Get("full_name").(string),
		Role:     d.Get("role").(string),
		Status:   d.Get("status").(string),
	}
	if v, ok := d.GetOk("group_ids"); ok {
		for _, gid := range v.([]interface{}) {
			user.GroupIDs = append(user.GroupIDs, gid.(string))
		}
	}

	created, err := c.CreateUser(user)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating user: %w", err))
	}

	d.SetId(created.ID)
	return resourceUserRead(ctx, d, meta)
}

func resourceUserRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	user, err := c.GetUser(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading user %s: %w", d.Id(), err))
	}

	d.Set("username", user.Username)
	d.Set("email", user.Email)
	d.Set("full_name", user.FullName)
	d.Set("role", user.Role)
	d.Set("status", user.Status)
	d.Set("group_ids", user.GroupIDs)
	d.Set("created_at", user.CreatedAt)
	d.Set("updated_at", user.UpdatedAt)

	return diags
}

func resourceUserUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	user := &client.User{
		Username: d.Get("username").(string),
		Email:    d.Get("email").(string),
		FullName: d.Get("full_name").(string),
		Role:     d.Get("role").(string),
		Status:   d.Get("status").(string),
	}
	if v, ok := d.GetOk("group_ids"); ok {
		for _, gid := range v.([]interface{}) {
			user.GroupIDs = append(user.GroupIDs, gid.(string))
		}
	}

	_, err := c.UpdateUser(d.Id(), user)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating user %s: %w", d.Id(), err))
	}

	return resourceUserRead(ctx, d, meta)
}

func resourceUserDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	err := c.DeleteUser(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting user %s: %w", d.Id(), err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_group
// ──────────────────────────────────────────────────────────────────────────────

func resourceGroup() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a group in OpenDirectory.",
		CreateContext: resourceGroupCreate,
		ReadContext:   resourceGroupRead,
		UpdateContext: resourceGroupUpdate,
		DeleteContext: resourceGroupDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Group name.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group description.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "static",
				Description: "Group type (static, dynamic).",
			},
			"member_ids": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of member user/device IDs.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"policy_ids": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of policy IDs assigned to this group.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the group was created.",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp of last update.",
			},
		},
	}
}

func resourceGroupCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	group := &client.Group{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Type:        d.Get("type").(string),
	}
	if v, ok := d.GetOk("member_ids"); ok {
		for _, m := range v.([]interface{}) {
			group.MemberIDs = append(group.MemberIDs, m.(string))
		}
	}
	if v, ok := d.GetOk("policy_ids"); ok {
		for _, p := range v.([]interface{}) {
			group.PolicyIDs = append(group.PolicyIDs, p.(string))
		}
	}

	created, err := c.CreateGroup(group)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating group: %w", err))
	}

	d.SetId(created.ID)
	return resourceGroupRead(ctx, d, meta)
}

func resourceGroupRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	group, err := c.GetGroup(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading group %s: %w", d.Id(), err))
	}

	d.Set("name", group.Name)
	d.Set("description", group.Description)
	d.Set("type", group.Type)
	d.Set("member_ids", group.MemberIDs)
	d.Set("policy_ids", group.PolicyIDs)
	d.Set("created_at", group.CreatedAt)
	d.Set("updated_at", group.UpdatedAt)

	return diags
}

func resourceGroupUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	group := &client.Group{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Type:        d.Get("type").(string),
	}
	if v, ok := d.GetOk("member_ids"); ok {
		for _, m := range v.([]interface{}) {
			group.MemberIDs = append(group.MemberIDs, m.(string))
		}
	}
	if v, ok := d.GetOk("policy_ids"); ok {
		for _, p := range v.([]interface{}) {
			group.PolicyIDs = append(group.PolicyIDs, p.(string))
		}
	}

	_, err := c.UpdateGroup(d.Id(), group)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating group %s: %w", d.Id(), err))
	}

	return resourceGroupRead(ctx, d, meta)
}

func resourceGroupDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	err := c.DeleteGroup(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting group %s: %w", d.Id(), err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_policy
// ──────────────────────────────────────────────────────────────────────────────

func resourcePolicy() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a policy in OpenDirectory.",
		CreateContext: resourcePolicyCreate,
		ReadContext:   resourcePolicyRead,
		UpdateContext: resourcePolicyUpdate,
		DeleteContext: resourcePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Policy name.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Policy description.",
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Policy type (security, compliance, configuration, restriction).",
			},
			"priority": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     100,
				Description: "Policy priority (lower number = higher priority).",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether the policy is enabled.",
			},
			"rules_json": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Policy rules as a JSON string.",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if v == "" {
						return
					}
					var js map[string]interface{}
					if err := json.Unmarshal([]byte(v), &js); err != nil {
						errs = append(errs, fmt.Errorf("%q must be valid JSON: %s", key, err))
					}
					return
				},
			},
			"targets": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of target device or group IDs this policy applies to.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the policy was created.",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp of last update.",
			},
		},
	}
}

func resourcePolicyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	policy := &client.Policy{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Type:        d.Get("type").(string),
		Priority:    d.Get("priority").(int),
		Enabled:     d.Get("enabled").(bool),
	}

	if v, ok := d.GetOk("rules_json"); ok && v.(string) != "" {
		var rules map[string]interface{}
		if err := json.Unmarshal([]byte(v.(string)), &rules); err != nil {
			return diag.FromErr(fmt.Errorf("error parsing rules_json: %w", err))
		}
		policy.Rules = rules
	}
	if v, ok := d.GetOk("targets"); ok {
		for _, t := range v.([]interface{}) {
			policy.Targets = append(policy.Targets, t.(string))
		}
	}

	created, err := c.CreatePolicy(policy)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating policy: %w", err))
	}

	d.SetId(created.ID)
	return resourcePolicyRead(ctx, d, meta)
}

func resourcePolicyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	policy, err := c.GetPolicy(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading policy %s: %w", d.Id(), err))
	}

	d.Set("name", policy.Name)
	d.Set("description", policy.Description)
	d.Set("type", policy.Type)
	d.Set("priority", policy.Priority)
	d.Set("enabled", policy.Enabled)
	d.Set("targets", policy.Targets)
	d.Set("created_at", policy.CreatedAt)
	d.Set("updated_at", policy.UpdatedAt)

	if policy.Rules != nil {
		rulesJSON, err := json.Marshal(policy.Rules)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error serializing rules: %w", err))
		}
		d.Set("rules_json", string(rulesJSON))
	}

	return diags
}

func resourcePolicyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	policy := &client.Policy{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Type:        d.Get("type").(string),
		Priority:    d.Get("priority").(int),
		Enabled:     d.Get("enabled").(bool),
	}

	if v, ok := d.GetOk("rules_json"); ok && v.(string) != "" {
		var rules map[string]interface{}
		if err := json.Unmarshal([]byte(v.(string)), &rules); err != nil {
			return diag.FromErr(fmt.Errorf("error parsing rules_json: %w", err))
		}
		policy.Rules = rules
	}
	if v, ok := d.GetOk("targets"); ok {
		for _, t := range v.([]interface{}) {
			policy.Targets = append(policy.Targets, t.(string))
		}
	}

	_, err := c.UpdatePolicy(d.Id(), policy)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating policy %s: %w", d.Id(), err))
	}

	return resourcePolicyRead(ctx, d, meta)
}

func resourcePolicyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	err := c.DeletePolicy(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting policy %s: %w", d.Id(), err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_wifi_profile
// ──────────────────────────────────────────────────────────────────────────────

func resourceWiFiProfile() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a WiFi network profile deployed via the OpenDirectory agent.",
		CreateContext: resourceWiFiProfileCreate,
		ReadContext:   resourceWiFiProfileRead,
		UpdateContext: resourceWiFiProfileUpdate,
		DeleteContext: resourceWiFiProfileDelete,
		Schema: map[string]*schema.Schema{
			"profile_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Server-assigned profile identifier.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the WiFi profile.",
			},
			"ssid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "WiFi network SSID.",
			},
			"security_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Security type (WPA2, WPA3, WPA2Enterprise, WPA3Enterprise, Open).",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "WiFi password (for WPA2/WPA3 personal).",
			},
			"auto_join": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Automatically join this network when in range.",
			},
			"hidden": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether the network SSID is hidden.",
			},
			"proxy_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Proxy type (none, manual, auto).",
			},
			"proxy_server": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Proxy server address.",
			},
			"proxy_port": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Proxy server port.",
			},
			"eap_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "EAP type for enterprise authentication (PEAP, TLS, TTLS).",
			},
			"certificate_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate ID for EAP-TLS authentication.",
			},
			"device_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Target device ID to deploy the WiFi profile to.",
			},
		},
	}
}

func resourceWiFiProfileCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	profile := &client.WiFiProfile{
		Name:          d.Get("name").(string),
		SSID:          d.Get("ssid").(string),
		SecurityType:  d.Get("security_type").(string),
		Password:      d.Get("password").(string),
		AutoJoin:      d.Get("auto_join").(bool),
		Hidden:        d.Get("hidden").(bool),
		ProxyType:     d.Get("proxy_type").(string),
		ProxyServer:   d.Get("proxy_server").(string),
		ProxyPort:     d.Get("proxy_port").(int),
		EAPType:       d.Get("eap_type").(string),
		CertificateID: d.Get("certificate_id").(string),
		DeviceID:      d.Get("device_id").(string),
	}

	created, err := c.ConfigureWiFi(profile)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating wifi profile: %w", err))
	}

	id := created.ProfileID
	if id == "" {
		id = created.ID
	}
	if id == "" {
		// Fallback composite ID
		id = fmt.Sprintf("%s/%s", profile.DeviceID, profile.SSID)
	}
	d.SetId(id)
	d.Set("profile_id", id)

	return resourceWiFiProfileRead(ctx, d, meta)
}

func resourceWiFiProfileRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	profile, err := c.GetWiFiProfile(deviceID, d.Id())
	if err != nil {
		// If the profile is not found, mark as gone so Terraform recreates it.
		d.SetId("")
		return diags
	}

	d.Set("name", profile.Name)
	d.Set("ssid", profile.SSID)
	d.Set("security_type", profile.SecurityType)
	d.Set("auto_join", profile.AutoJoin)
	d.Set("hidden", profile.Hidden)
	d.Set("proxy_type", profile.ProxyType)
	d.Set("proxy_server", profile.ProxyServer)
	d.Set("proxy_port", profile.ProxyPort)
	d.Set("eap_type", profile.EAPType)
	d.Set("certificate_id", profile.CertificateID)
	d.Set("profile_id", profile.ProfileID)

	return diags
}

func resourceWiFiProfileUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	profile := &client.WiFiProfile{
		ProfileID:     d.Id(),
		Name:          d.Get("name").(string),
		SSID:          d.Get("ssid").(string),
		SecurityType:  d.Get("security_type").(string),
		Password:      d.Get("password").(string),
		AutoJoin:      d.Get("auto_join").(bool),
		Hidden:        d.Get("hidden").(bool),
		ProxyType:     d.Get("proxy_type").(string),
		ProxyServer:   d.Get("proxy_server").(string),
		ProxyPort:     d.Get("proxy_port").(int),
		EAPType:       d.Get("eap_type").(string),
		CertificateID: d.Get("certificate_id").(string),
		DeviceID:      d.Get("device_id").(string),
	}

	_, err := c.ConfigureWiFi(profile)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating wifi profile: %w", err))
	}

	return resourceWiFiProfileRead(ctx, d, meta)
}

func resourceWiFiProfileDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	ssid := d.Get("ssid").(string)

	err := c.RemoveWiFi(deviceID, d.Id(), ssid)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting wifi profile: %w", err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_vpn_profile
// ──────────────────────────────────────────────────────────────────────────────

func resourceVPNProfile() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a VPN profile deployed via the OpenDirectory agent.",
		CreateContext: resourceVPNProfileCreate,
		ReadContext:   resourceVPNProfileRead,
		UpdateContext: resourceVPNProfileUpdate,
		DeleteContext: resourceVPNProfileDelete,
		Schema: map[string]*schema.Schema{
			"profile_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Server-assigned profile identifier.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the VPN profile.",
			},
			"vpn_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "VPN type (IKEv2, IPSec, L2TP, OpenVPN, WireGuard).",
			},
			"server": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "VPN server address.",
			},
			"remote_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Remote identifier for IKEv2.",
			},
			"local_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Local identifier for IKEv2.",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "VPN username.",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "VPN password.",
			},
			"shared_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "IPSec shared secret.",
			},
			"certificate_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate ID for certificate-based authentication.",
			},
			"on_demand_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable VPN on-demand.",
			},
			"on_demand_rules": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "On-demand rules as JSON string.",
			},
			"device_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Target device ID to deploy the VPN profile to.",
			},
		},
	}
}

func resourceVPNProfileCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	profile := &client.VPNProfile{
		Name:            d.Get("name").(string),
		VPNType:         d.Get("vpn_type").(string),
		Server:          d.Get("server").(string),
		RemoteID:        d.Get("remote_id").(string),
		LocalID:         d.Get("local_id").(string),
		Username:        d.Get("username").(string),
		Password:        d.Get("password").(string),
		SharedSecret:    d.Get("shared_secret").(string),
		CertificateID:   d.Get("certificate_id").(string),
		OnDemandEnabled: d.Get("on_demand_enabled").(bool),
		OnDemandRules:   d.Get("on_demand_rules").(string),
		DeviceID:        d.Get("device_id").(string),
	}

	created, err := c.ConfigureVPN(profile)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating vpn profile: %w", err))
	}

	id := created.ProfileID
	if id == "" {
		id = created.ID
	}
	if id == "" {
		id = fmt.Sprintf("%s/%s", profile.DeviceID, profile.Name)
	}
	d.SetId(id)
	d.Set("profile_id", id)

	return resourceVPNProfileRead(ctx, d, meta)
}

func resourceVPNProfileRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	profile, err := c.GetVPNProfile(deviceID, d.Id())
	if err != nil {
		d.SetId("")
		return diags
	}

	d.Set("name", profile.Name)
	d.Set("vpn_type", profile.VPNType)
	d.Set("server", profile.Server)
	d.Set("remote_id", profile.RemoteID)
	d.Set("local_id", profile.LocalID)
	d.Set("username", profile.Username)
	d.Set("certificate_id", profile.CertificateID)
	d.Set("on_demand_enabled", profile.OnDemandEnabled)
	d.Set("on_demand_rules", profile.OnDemandRules)
	d.Set("profile_id", profile.ProfileID)

	return diags
}

func resourceVPNProfileUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	profile := &client.VPNProfile{
		ProfileID:       d.Id(),
		Name:            d.Get("name").(string),
		VPNType:         d.Get("vpn_type").(string),
		Server:          d.Get("server").(string),
		RemoteID:        d.Get("remote_id").(string),
		LocalID:         d.Get("local_id").(string),
		Username:        d.Get("username").(string),
		Password:        d.Get("password").(string),
		SharedSecret:    d.Get("shared_secret").(string),
		CertificateID:   d.Get("certificate_id").(string),
		OnDemandEnabled: d.Get("on_demand_enabled").(bool),
		OnDemandRules:   d.Get("on_demand_rules").(string),
		DeviceID:        d.Get("device_id").(string),
	}

	_, err := c.ConfigureVPN(profile)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating vpn profile: %w", err))
	}

	return resourceVPNProfileRead(ctx, d, meta)
}

func resourceVPNProfileDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	err := c.RemoveVPN(deviceID, d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting vpn profile: %w", err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_update_policy
// ──────────────────────────────────────────────────────────────────────────────

func resourceUpdatePolicy() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages an OS/software update policy via the OpenDirectory agent.",
		CreateContext: resourceUpdatePolicyCreate,
		ReadContext:   resourceUpdatePolicyRead,
		UpdateContext: resourceUpdatePolicyUpdate,
		DeleteContext: resourceUpdatePolicyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Update policy name.",
			},
			"device_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Target device ID.",
			},
			"auto_update": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable automatic updates.",
			},
			"maintenance_window": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cron expression or time window for maintenance (e.g. 'Sun 02:00-06:00').",
			},
			"deferral_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     0,
				Description: "Number of days to defer updates after release.",
			},
			"force_restart": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Force restart after applying updates.",
			},
			"allow_user_defer": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Allow the user to defer the update.",
			},
			"max_deferrals": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     3,
				Description: "Maximum number of times a user can defer an update.",
			},
			"include_beta": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Include beta/preview updates.",
			},
			"allowed_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Semver range of allowed versions (e.g. '>=14.0 <15.0').",
			},
			"blocked_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-separated list of blocked version strings.",
			},
		},
	}
}

func resourceUpdatePolicyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	policy := &client.UpdatePolicy{
		Name:              d.Get("name").(string),
		DeviceID:          d.Get("device_id").(string),
		AutoUpdate:        d.Get("auto_update").(bool),
		MaintenanceWindow: d.Get("maintenance_window").(string),
		DeferralDays:      d.Get("deferral_days").(int),
		ForceRestart:      d.Get("force_restart").(bool),
		AllowUserDefer:    d.Get("allow_user_defer").(bool),
		MaxDeferrals:      d.Get("max_deferrals").(int),
		IncludeBeta:       d.Get("include_beta").(bool),
		AllowedVersions:   d.Get("allowed_versions").(string),
		BlockedVersions:   d.Get("blocked_versions").(string),
	}

	created, err := c.ConfigureUpdatePolicy(policy)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating update policy: %w", err))
	}

	id := created.ID
	if id == "" {
		id = policy.DeviceID
	}
	d.SetId(id)

	return resourceUpdatePolicyRead(ctx, d, meta)
}

func resourceUpdatePolicyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	policy, err := c.GetUpdatePolicyStatus(deviceID)
	if err != nil {
		d.SetId("")
		return diags
	}

	d.Set("name", policy.Name)
	d.Set("auto_update", policy.AutoUpdate)
	d.Set("maintenance_window", policy.MaintenanceWindow)
	d.Set("deferral_days", policy.DeferralDays)
	d.Set("force_restart", policy.ForceRestart)
	d.Set("allow_user_defer", policy.AllowUserDefer)
	d.Set("max_deferrals", policy.MaxDeferrals)
	d.Set("include_beta", policy.IncludeBeta)
	d.Set("allowed_versions", policy.AllowedVersions)
	d.Set("blocked_versions", policy.BlockedVersions)

	return diags
}

func resourceUpdatePolicyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	policy := &client.UpdatePolicy{
		Name:              d.Get("name").(string),
		DeviceID:          d.Get("device_id").(string),
		AutoUpdate:        d.Get("auto_update").(bool),
		MaintenanceWindow: d.Get("maintenance_window").(string),
		DeferralDays:      d.Get("deferral_days").(int),
		ForceRestart:      d.Get("force_restart").(bool),
		AllowUserDefer:    d.Get("allow_user_defer").(bool),
		MaxDeferrals:      d.Get("max_deferrals").(int),
		IncludeBeta:       d.Get("include_beta").(bool),
		AllowedVersions:   d.Get("allowed_versions").(string),
		BlockedVersions:   d.Get("blocked_versions").(string),
	}

	_, err := c.ConfigureUpdatePolicy(policy)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating update policy: %w", err))
	}

	return resourceUpdatePolicyRead(ctx, d, meta)
}

func resourceUpdatePolicyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	err := c.DeleteUpdatePolicy(deviceID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting update policy for device %s: %w", deviceID, err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource: opendirectory_certificate
// ──────────────────────────────────────────────────────────────────────────────

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		Description:   "Issues and manages certificates via the OpenDirectory PKI.",
		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Common name (CN) for the certificate.",
			},
			"organization": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Organization (O).",
			},
			"organization_unit": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Organizational Unit (OU).",
			},
			"country": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Country code (C).",
			},
			"state": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "State or province (ST).",
			},
			"locality": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Locality (L).",
			},
			"key_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "RSA",
				ForceNew:    true,
				Description: "Key algorithm (RSA, ECDSA).",
			},
			"key_size": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     2048,
				ForceNew:    true,
				Description: "Key size in bits (2048, 4096 for RSA; 256, 384 for ECDSA).",
			},
			"validity_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     365,
				ForceNew:    true,
				Description: "Certificate validity period in days.",
			},
			"usage": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "client",
				ForceNew:    true,
				Description: "Certificate usage (client, server, codesigning, email).",
			},
			"sans": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Subject alternative names (comma-separated DNS names or IPs).",
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate status (active, expired, revoked).",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate serial number.",
			},
			"fingerprint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "SHA-256 fingerprint.",
			},
			"issued_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the certificate was issued.",
			},
			"expires_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the certificate expires.",
			},
		},
	}
}

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)

	cert := &client.Certificate{
		CommonName:       d.Get("common_name").(string),
		Organization:     d.Get("organization").(string),
		OrganizationUnit: d.Get("organization_unit").(string),
		Country:          d.Get("country").(string),
		State:            d.Get("state").(string),
		Locality:         d.Get("locality").(string),
		KeyType:          d.Get("key_type").(string),
		KeySize:          d.Get("key_size").(int),
		ValidityDays:     d.Get("validity_days").(int),
		Usage:            d.Get("usage").(string),
		SANs:             d.Get("sans").(string),
	}

	issued, err := c.IssueCertificate(cert)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error issuing certificate: %w", err))
	}

	d.SetId(issued.ID)
	return resourceCertificateRead(ctx, d, meta)
}

func resourceCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	cert, err := c.GetCertificate(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading certificate %s: %w", d.Id(), err))
	}

	d.Set("common_name", cert.CommonName)
	d.Set("organization", cert.Organization)
	d.Set("organization_unit", cert.OrganizationUnit)
	d.Set("country", cert.Country)
	d.Set("state", cert.State)
	d.Set("locality", cert.Locality)
	d.Set("key_type", cert.KeyType)
	d.Set("key_size", cert.KeySize)
	d.Set("validity_days", cert.ValidityDays)
	d.Set("usage", cert.Usage)
	d.Set("sans", cert.SANs)
	d.Set("status", cert.Status)
	d.Set("serial_number", cert.SerialNumber)
	d.Set("fingerprint", cert.Fingerprint)
	d.Set("issued_at", cert.IssuedAt)
	d.Set("expires_at", cert.ExpiresAt)

	return diags
}

func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Certificates are immutable; on any change ForceNew triggers recreation.
	// If somehow called, renew the certificate.
	c := meta.(*client.Client)

	renewed, err := c.RenewCertificate(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error renewing certificate %s: %w", d.Id(), err))
	}

	if renewed.ID != "" && renewed.ID != d.Id() {
		d.SetId(renewed.ID)
	}

	return resourceCertificateRead(ctx, d, meta)
}

func resourceCertificateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	err := c.RevokeCertificate(d.Id())
	if err != nil {
		return diag.FromErr(fmt.Errorf("error revoking certificate %s: %w", d.Id(), err))
	}

	d.SetId("")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Data Source: opendirectory_devices
// ──────────────────────────────────────────────────────────────────────────────

func dataSourceDevices() *schema.Resource {
	return &schema.Resource{
		Description: "Retrieves a list of all devices from OpenDirectory.",
		ReadContext: dataSourceDevicesRead,
		Schema: map[string]*schema.Schema{
			"platform": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter devices by platform (windows, macos, linux).",
			},
			"status": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter devices by status (active, inactive, pending).",
			},
			"devices": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of devices.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Device ID.",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Device name.",
						},
						"hostname": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Hostname.",
						},
						"platform": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Platform.",
						},
						"os_version": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "OS version.",
						},
						"serial_number": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Serial number.",
						},
						"model": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Device model.",
						},
						"status": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Device status.",
						},
						"owner": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Owner user ID.",
						},
						"enrolled_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Enrollment timestamp.",
						},
						"last_seen_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Last seen timestamp.",
						},
						"compliance_status": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Compliance status.",
						},
					},
				},
			},
		},
	}
}

func dataSourceDevicesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	devices, err := c.GetDevices()
	if err != nil {
		return diag.FromErr(fmt.Errorf("error listing devices: %w", err))
	}

	platformFilter := d.Get("platform").(string)
	statusFilter := d.Get("status").(string)

	deviceList := make([]map[string]interface{}, 0, len(devices))
	for _, dev := range devices {
		if platformFilter != "" && dev.Platform != platformFilter {
			continue
		}
		if statusFilter != "" && dev.Status != statusFilter {
			continue
		}
		deviceList = append(deviceList, map[string]interface{}{
			"id":                dev.ID,
			"name":              dev.Name,
			"hostname":          dev.Hostname,
			"platform":          dev.Platform,
			"os_version":        dev.OSVersion,
			"serial_number":     dev.SerialNumber,
			"model":             dev.Model,
			"status":            dev.Status,
			"owner":             dev.Owner,
			"enrolled_at":       dev.EnrolledAt,
			"last_seen_at":      dev.LastSeenAt,
			"compliance_status": dev.ComplianceStatus,
		})
	}

	if err := d.Set("devices", deviceList); err != nil {
		return diag.FromErr(fmt.Errorf("error setting devices: %w", err))
	}

	d.SetId("opendirectory-devices")
	return diags
}

// ──────────────────────────────────────────────────────────────────────────────
// Data Source: opendirectory_compliance_status
// ──────────────────────────────────────────────────────────────────────────────

func dataSourceComplianceStatus() *schema.Resource {
	return &schema.Resource{
		Description: "Retrieves the compliance status for a specific device.",
		ReadContext: dataSourceComplianceStatusRead,
		Schema: map[string]*schema.Schema{
			"device_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Device ID to check compliance for.",
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Overall compliance status (compliant, non_compliant, unknown).",
			},
			"score": {
				Type:        schema.TypeFloat,
				Computed:    true,
				Description: "Compliance score (0.0 to 100.0).",
			},
			"last_scan_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp of the last compliance scan.",
			},
			"violations_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Compliance violations as a JSON string.",
			},
		},
	}
}

func dataSourceComplianceStatusRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*client.Client)
	var diags diag.Diagnostics

	deviceID := d.Get("device_id").(string)
	status, err := c.GetComplianceStatus(deviceID)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading compliance status for device %s: %w", deviceID, err))
	}

	d.SetId(deviceID)
	d.Set("status", status.Status)
	d.Set("score", status.Score)
	d.Set("last_scan_at", status.LastScanAt)

	if status.Violations != nil {
		violationsJSON, err := json.Marshal(status.Violations)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error serializing violations: %w", err))
		}
		d.Set("violations_json", string(violationsJSON))
	} else {
		d.Set("violations_json", "[]")
	}

	return diags
}
