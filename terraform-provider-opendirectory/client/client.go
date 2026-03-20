package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client manages communication with the OpenDirectory API.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new OpenDirectory API client.
func NewClient(baseURL, apiKey string, timeout int) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

// APIResponse is the standard envelope returned by the OpenDirectory API.
type APIResponse struct {
	Success   bool            `json:"success"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Details   string          `json:"details,omitempty"`
	RequestID string          `json:"requestId,omitempty"`
}

// ---------- Device ----------

type Device struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	Hostname       string   `json:"hostname,omitempty"`
	Platform       string   `json:"platform"`
	OSVersion      string   `json:"osVersion,omitempty"`
	SerialNumber   string   `json:"serialNumber,omitempty"`
	Model          string   `json:"model,omitempty"`
	Status         string   `json:"status,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	GroupID        string   `json:"groupId,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	EnrolledAt     string   `json:"enrolledAt,omitempty"`
	LastSeenAt     string   `json:"lastSeenAt,omitempty"`
	ComplianceStatus string `json:"complianceStatus,omitempty"`
}

// ---------- User ----------

type User struct {
	ID        string   `json:"id,omitempty"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FullName  string   `json:"fullName,omitempty"`
	Role      string   `json:"role,omitempty"`
	Status    string   `json:"status,omitempty"`
	GroupIDs  []string `json:"groupIds,omitempty"`
	CreatedAt string   `json:"createdAt,omitempty"`
	UpdatedAt string   `json:"updatedAt,omitempty"`
}

// ---------- Group ----------

type Group struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type,omitempty"`
	MemberIDs   []string `json:"memberIds,omitempty"`
	PolicyIDs   []string `json:"policyIds,omitempty"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
}

// ---------- Policy ----------

type Policy struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Type        string                 `json:"type"`
	Priority    int                    `json:"priority,omitempty"`
	Enabled     bool                   `json:"enabled"`
	Rules       map[string]interface{} `json:"rules,omitempty"`
	Targets     []string               `json:"targets,omitempty"`
	CreatedAt   string                 `json:"createdAt,omitempty"`
	UpdatedAt   string                 `json:"updatedAt,omitempty"`
}

// ---------- WiFi Profile ----------

type WiFiProfile struct {
	ID             string `json:"id,omitempty"`
	ProfileID      string `json:"profileId,omitempty"`
	Name           string `json:"name"`
	SSID           string `json:"ssid"`
	SecurityType   string `json:"securityType"`
	Password       string `json:"password,omitempty"`
	AutoJoin       bool   `json:"autoJoin"`
	Hidden         bool   `json:"hidden"`
	ProxyType      string `json:"proxyType,omitempty"`
	ProxyServer    string `json:"proxyServer,omitempty"`
	ProxyPort      int    `json:"proxyPort,omitempty"`
	EAPType        string `json:"eapType,omitempty"`
	CertificateID  string `json:"certificateId,omitempty"`
	DeviceID       string `json:"deviceId,omitempty"`
}

// ---------- VPN Profile ----------

type VPNProfile struct {
	ID              string `json:"id,omitempty"`
	ProfileID       string `json:"profileId,omitempty"`
	Name            string `json:"name"`
	VPNType         string `json:"vpnType"`
	Server          string `json:"server"`
	RemoteID        string `json:"remoteId,omitempty"`
	LocalID         string `json:"localId,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	SharedSecret    string `json:"sharedSecret,omitempty"`
	CertificateID   string `json:"certificateId,omitempty"`
	OnDemandEnabled bool   `json:"onDemandEnabled"`
	OnDemandRules   string `json:"onDemandRules,omitempty"`
	DeviceID        string `json:"deviceId,omitempty"`
}

// ---------- Update Policy ----------

type UpdatePolicy struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name"`
	AutoUpdate         bool   `json:"autoUpdate"`
	MaintenanceWindow  string `json:"maintenanceWindow,omitempty"`
	DeferralDays       int    `json:"deferralDays,omitempty"`
	ForceRestart       bool   `json:"forceRestart"`
	AllowUserDefer     bool   `json:"allowUserDefer"`
	MaxDeferrals       int    `json:"maxDeferrals,omitempty"`
	IncludeBeta        bool   `json:"includeBeta"`
	AllowedVersions    string `json:"allowedVersions,omitempty"`
	BlockedVersions    string `json:"blockedVersions,omitempty"`
	DeviceID           string `json:"deviceId,omitempty"`
}

// ---------- Certificate ----------

type Certificate struct {
	ID               string `json:"id,omitempty"`
	CommonName       string `json:"commonName"`
	Organization     string `json:"organization,omitempty"`
	OrganizationUnit string `json:"organizationUnit,omitempty"`
	Country          string `json:"country,omitempty"`
	State            string `json:"state,omitempty"`
	Locality         string `json:"locality,omitempty"`
	KeyType          string `json:"keyType,omitempty"`
	KeySize          int    `json:"keySize,omitempty"`
	ValidityDays     int    `json:"validityDays,omitempty"`
	Usage            string `json:"usage,omitempty"`
	SANs             string `json:"sans,omitempty"`
	Status           string `json:"status,omitempty"`
	IssuedAt         string `json:"issuedAt,omitempty"`
	ExpiresAt        string `json:"expiresAt,omitempty"`
	SerialNumber     string `json:"serialNumber,omitempty"`
	Fingerprint      string `json:"fingerprint,omitempty"`
}

// ---------- Compliance Status ----------

type ComplianceStatus struct {
	DeviceID         string                   `json:"deviceId"`
	Status           string                   `json:"status"`
	LastScanAt       string                   `json:"lastScanAt"`
	Violations       []map[string]interface{} `json:"violations"`
	Score            float64                  `json:"score"`
}

// ---------- HTTP helpers ----------

func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiResp APIResponse
		if json.Unmarshal(respBody, &apiResp) == nil && apiResp.Error != "" {
			return nil, fmt.Errorf("API error (HTTP %d): %s — %s", resp.StatusCode, apiResp.Error, apiResp.Details)
		}
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// extractData unmarshals the standard { success, data } envelope and returns data bytes.
func (c *Client) extractData(raw []byte) (json.RawMessage, error) {
	var apiResp APIResponse
	if err := json.Unmarshal(raw, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}
	if !apiResp.Success {
		return nil, fmt.Errorf("API returned success=false: %s", apiResp.Error)
	}
	return apiResp.Data, nil
}

// ---------- Device CRUD ----------

func (c *Client) GetDevices() ([]Device, error) {
	raw, err := c.doRequest(http.MethodGet, "/api/devices", nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var devices []Device
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, fmt.Errorf("failed to parse devices: %w", err)
	}
	return devices, nil
}

func (c *Client) GetDevice(id string) (*Device, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/devices/%s", id), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var device Device
	if err := json.Unmarshal(data, &device); err != nil {
		return nil, fmt.Errorf("failed to parse device: %w", err)
	}
	return &device, nil
}

func (c *Client) CreateDevice(device *Device) (*Device, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/devices", device)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created Device
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse created device: %w", err)
	}
	return &created, nil
}

func (c *Client) UpdateDevice(id string, device *Device) (*Device, error) {
	raw, err := c.doRequest(http.MethodPut, fmt.Sprintf("/api/devices/%s", id), device)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var updated Device
	if err := json.Unmarshal(data, &updated); err != nil {
		return nil, fmt.Errorf("failed to parse updated device: %w", err)
	}
	return &updated, nil
}

func (c *Client) DeleteDevice(id string) error {
	_, err := c.doRequest(http.MethodDelete, fmt.Sprintf("/api/devices/%s", id), nil)
	return err
}

// ---------- User CRUD ----------

func (c *Client) GetUser(id string) (*User, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/users/%s", id), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user: %w", err)
	}
	return &user, nil
}

func (c *Client) CreateUser(user *User) (*User, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/users", user)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created User
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse created user: %w", err)
	}
	return &created, nil
}

func (c *Client) UpdateUser(id string, user *User) (*User, error) {
	raw, err := c.doRequest(http.MethodPut, fmt.Sprintf("/api/users/%s", id), user)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var updated User
	if err := json.Unmarshal(data, &updated); err != nil {
		return nil, fmt.Errorf("failed to parse updated user: %w", err)
	}
	return &updated, nil
}

func (c *Client) DeleteUser(id string) error {
	_, err := c.doRequest(http.MethodDelete, fmt.Sprintf("/api/users/%s", id), nil)
	return err
}

// ---------- Group CRUD ----------

func (c *Client) GetGroup(id string) (*Group, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/groups/%s", id), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var group Group
	if err := json.Unmarshal(data, &group); err != nil {
		return nil, fmt.Errorf("failed to parse group: %w", err)
	}
	return &group, nil
}

func (c *Client) CreateGroup(group *Group) (*Group, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/groups", group)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created Group
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse created group: %w", err)
	}
	return &created, nil
}

func (c *Client) UpdateGroup(id string, group *Group) (*Group, error) {
	raw, err := c.doRequest(http.MethodPut, fmt.Sprintf("/api/groups/%s", id), group)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var updated Group
	if err := json.Unmarshal(data, &updated); err != nil {
		return nil, fmt.Errorf("failed to parse updated group: %w", err)
	}
	return &updated, nil
}

func (c *Client) DeleteGroup(id string) error {
	_, err := c.doRequest(http.MethodDelete, fmt.Sprintf("/api/groups/%s", id), nil)
	return err
}

// ---------- Policy CRUD ----------

func (c *Client) GetPolicy(id string) (*Policy, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/policies/%s", id), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}
	return &policy, nil
}

func (c *Client) CreatePolicy(policy *Policy) (*Policy, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/policies", policy)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created Policy
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse created policy: %w", err)
	}
	return &created, nil
}

func (c *Client) UpdatePolicy(id string, policy *Policy) (*Policy, error) {
	raw, err := c.doRequest(http.MethodPut, fmt.Sprintf("/api/policies/%s", id), policy)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var updated Policy
	if err := json.Unmarshal(data, &updated); err != nil {
		return nil, fmt.Errorf("failed to parse updated policy: %w", err)
	}
	return &updated, nil
}

func (c *Client) DeletePolicy(id string) error {
	_, err := c.doRequest(http.MethodDelete, fmt.Sprintf("/api/policies/%s", id), nil)
	return err
}

// ---------- WiFi Profile CRUD ----------

func (c *Client) ConfigureWiFi(profile *WiFiProfile) (*WiFiProfile, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/agent/network/configure-wifi", profile)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created WiFiProfile
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse wifi profile: %w", err)
	}
	return &created, nil
}

func (c *Client) GetWiFiProfile(deviceID string, profileID string) (*WiFiProfile, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/agent/network/status/%s", deviceID), nil)
	if err != nil {
		return nil, err
	}
	// The status endpoint returns the full device network state; we parse the wifi profiles from it.
	var status struct {
		WiFiProfiles []WiFiProfile `json:"wifiProfiles"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		// Try envelope format
		data, extractErr := c.extractData(raw)
		if extractErr != nil {
			return nil, fmt.Errorf("failed to parse network status: %w", err)
		}
		if err2 := json.Unmarshal(data, &status); err2 != nil {
			return nil, fmt.Errorf("failed to parse wifi profiles from status: %w", err2)
		}
	}
	for _, p := range status.WiFiProfiles {
		if p.ProfileID == profileID || p.ID == profileID {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("wifi profile %s not found on device %s", profileID, deviceID)
}

func (c *Client) RemoveWiFi(deviceID, profileID, ssid string) error {
	body := map[string]string{
		"deviceId":  deviceID,
		"profileId": profileID,
		"ssid":      ssid,
	}
	_, err := c.doRequest(http.MethodPost, "/api/agent/network/remove-wifi", body)
	return err
}

// ---------- VPN Profile CRUD ----------

func (c *Client) ConfigureVPN(profile *VPNProfile) (*VPNProfile, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/agent/network/configure-vpn", profile)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created VPNProfile
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse vpn profile: %w", err)
	}
	return &created, nil
}

func (c *Client) GetVPNProfile(deviceID string, profileID string) (*VPNProfile, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/agent/network/status/%s", deviceID), nil)
	if err != nil {
		return nil, err
	}
	var status struct {
		VPNProfiles []VPNProfile `json:"vpnProfiles"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		data, extractErr := c.extractData(raw)
		if extractErr != nil {
			return nil, fmt.Errorf("failed to parse network status: %w", err)
		}
		if err2 := json.Unmarshal(data, &status); err2 != nil {
			return nil, fmt.Errorf("failed to parse vpn profiles from status: %w", err2)
		}
	}
	for _, p := range status.VPNProfiles {
		if p.ProfileID == profileID || p.ID == profileID {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("vpn profile %s not found on device %s", profileID, deviceID)
}

func (c *Client) RemoveVPN(deviceID, profileID string) error {
	body := map[string]string{
		"deviceId":  deviceID,
		"profileId": profileID,
	}
	_, err := c.doRequest(http.MethodPost, "/api/agent/network/remove-vpn", body)
	return err
}

// ---------- Update Policy CRUD ----------

func (c *Client) ConfigureUpdatePolicy(policy *UpdatePolicy) (*UpdatePolicy, error) {
	body := map[string]interface{}{
		"deviceId": policy.DeviceID,
		"policy":   policy,
	}
	raw, err := c.doRequest(http.MethodPost, "/api/agent/update/configure", body)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var created UpdatePolicy
	if err := json.Unmarshal(data, &created); err != nil {
		return nil, fmt.Errorf("failed to parse update policy: %w", err)
	}
	return &created, nil
}

func (c *Client) GetUpdatePolicyStatus(deviceID string) (*UpdatePolicy, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/agent/update/status/%s", deviceID), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var policy UpdatePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse update policy status: %w", err)
	}
	return &policy, nil
}

func (c *Client) DeleteUpdatePolicy(deviceID string) error {
	body := map[string]interface{}{
		"deviceId": deviceID,
		"policy": map[string]interface{}{
			"autoUpdate": false,
			"name":       "",
		},
	}
	_, err := c.doRequest(http.MethodPost, "/api/agent/update/configure", body)
	return err
}

// ---------- Certificate CRUD ----------

func (c *Client) GetCertificates() ([]Certificate, error) {
	raw, err := c.doRequest(http.MethodGet, "/api/certificates", nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var certs []Certificate
	if err := json.Unmarshal(data, &certs); err != nil {
		return nil, fmt.Errorf("failed to parse certificates: %w", err)
	}
	return certs, nil
}

func (c *Client) GetCertificate(id string) (*Certificate, error) {
	certs, err := c.GetCertificates()
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if cert.ID == id {
			return &cert, nil
		}
	}
	return nil, fmt.Errorf("certificate %s not found", id)
}

func (c *Client) IssueCertificate(cert *Certificate) (*Certificate, error) {
	raw, err := c.doRequest(http.MethodPost, "/api/certificates/issue", cert)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var issued Certificate
	if err := json.Unmarshal(data, &issued); err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}
	return &issued, nil
}

func (c *Client) RenewCertificate(id string) (*Certificate, error) {
	raw, err := c.doRequest(http.MethodPost, fmt.Sprintf("/api/certificates/%s/renew", id), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var renewed Certificate
	if err := json.Unmarshal(data, &renewed); err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %w", err)
	}
	return &renewed, nil
}

func (c *Client) RevokeCertificate(id string) error {
	_, err := c.doRequest(http.MethodPost, fmt.Sprintf("/api/certificates/%s/revoke", id), nil)
	return err
}

// ---------- Compliance ----------

func (c *Client) GetComplianceStatus(deviceID string) (*ComplianceStatus, error) {
	raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/compliance/scan/%s", deviceID), nil)
	if err != nil {
		return nil, err
	}
	data, err := c.extractData(raw)
	if err != nil {
		return nil, err
	}
	var status ComplianceStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to parse compliance status: %w", err)
	}
	return &status, nil
}
