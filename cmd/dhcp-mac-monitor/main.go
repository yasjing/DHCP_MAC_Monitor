package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Listen                  string `json:"listen"`
	Port                    int    `json:"port"`
	DHCPServer              string `json:"dhcp_server"`
	PollIntervalSeconds     int    `json:"poll_interval_seconds"`
	DenySyncIntervalSeconds int    `json:"deny_sync_interval_seconds"`
}

type Device struct {
	MAC              string          `json:"mac"`
	Disabled         bool            `json:"disabled,omitempty"`
	Name             string          `json:"name"`
	Note             string          `json:"note"`
	LastIP           string          `json:"last_ip"`
	Hostname         string          `json:"hostname"`
	Scope            string          `json:"scope"`
	LastSeen         string          `json:"last_seen"`
	OnlineSince      string          `json:"online_since,omitempty"`
	IsOnline         bool            `json:"is_online,omitempty"`
	MissedChecks     int             `json:"missed_checks,omitempty"`
	LastOfflineAt    string          `json:"last_offline_at,omitempty"`
	LastLeaseExpiry  string          `json:"last_lease_expiry,omitempty"`
	ActiveLeaseCount int             `json:"active_lease_count,omitempty"`
	ActiveLeases     []LeaseSnapshot `json:"active_leases,omitempty"`
	OnlineDates      []string        `json:"online_dates,omitempty"`
	Reservation      *Reservation    `json:"reservation,omitempty"`
	MultiLease       MultiLeaseState `json:"multi_lease,omitempty"`
	CreatedAt        string          `json:"created_at"`
	CreatedBy        string          `json:"created_by"`
	UpdatedAt        string          `json:"updated_at"`
	UpdatedBy        string          `json:"updated_by"`
}

type Reservation struct {
	IP    string `json:"ip"`
	Scope string `json:"scope"`
	VLAN  string `json:"vlan,omitempty"`
	Name  string `json:"name,omitempty"`
}
type ScopeInfo struct {
	Scope string `json:"scope"`
	Name  string `json:"name"`
	Start string `json:"start"`
	End   string `json:"end"`
	Mask  string `json:"mask"`
	State string `json:"state"`
	VLAN  string `json:"vlan"`
}
type ReservationInfo struct {
	Scope       string `json:"scope"`
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Name        string `json:"name"`
	Description string `json:"description"`
}
type DHCPTopology struct {
	Scopes       []ScopeInfo       `json:"scopes"`
	Reservations []ReservationInfo `json:"reservations"`
}
type LeaseObservation struct {
	Time        string `json:"time"`
	ReachableIP string `json:"reachable_ip"`
	Scope       string `json:"scope"`
}
type MultiLeaseState struct {
	FirstSeen    string             `json:"first_seen,omitempty"`
	CandidateIP  string             `json:"candidate_ip,omitempty"`
	StaleIPs     []string           `json:"stale_ips,omitempty"`
	Observations []LeaseObservation `json:"observations,omitempty"`
	Switches     int                `json:"switches,omitempty"`
	Mobile       bool               `json:"mobile,omitempty"`
}
type DeletedDevice struct {
	DeletedAt string `json:"deleted_at"`
	DeletedBy string `json:"deleted_by"`
	Reason    string `json:"reason"`
	Snapshot  Device `json:"snapshot"`
}

type User struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"password_hash"`
	CreatedAt    string `json:"created_at"`
	CreatedBy    string `json:"created_by"`
	Enabled      bool   `json:"enabled"`
}

type Audit struct {
	Time     string `json:"time"`
	Username string `json:"username"`
	Action   string `json:"action"`
	MAC      string `json:"mac,omitempty"`
	Detail   string `json:"detail"`
	ClientIP string `json:"client_ip"`
}

type Persist struct {
	Devices    map[string]*Device `json:"devices"`
	Users      map[string]*User   `json:"users"`
	Audit      []Audit            `json:"audit"`
	RecycleBin []DeletedDevice    `json:"recycle_bin,omitempty"`
}

type Session struct {
	Username string
	Expires  time.Time
}
type Lease struct{ MAC, IP, Hostname, Scope string }
type LeaseSnapshot struct {
	IP           string `json:"ip"`
	Hostname     string `json:"hostname"`
	Scope        string `json:"scope"`
	AddressState string `json:"address_state"`
	LeaseExpiry  string `json:"lease_expiry"`
}
type AllowRow struct {
	MAC  string `json:"mac"`
	Note string `json:"note"`
}
type LeaseRow struct {
	MAC          string `json:"mac"`
	IP           string `json:"ip"`
	Hostname     string `json:"hostname"`
	Scope        string `json:"scope"`
	AddressState string `json:"address_state"`
	LeaseExpiry  string `json:"lease_expiry"`
}

var (
	cfg          Config
	baseDir      string
	dataPath     string
	state        Persist
	mu           sync.RWMutex
	sessions     = map[string]Session{}
	sessionMu    sync.Mutex
	lastSyncMu   sync.RWMutex
	scheduleMu   sync.RWMutex
	nextLeaseDue time.Time
	nextDenyDue  time.Time
	lastSync     = map[string]interface{}{
		"time": "", "ok": false, "message": "Not synced yet",
		"last_lease_check": "", "next_lease_check": "", "lease_duration_ms": int64(0), "lease_count": 0, "matched_count": 0, "multi_lease_macs": 0,
		"allow_mode": "realtime", "last_allow_sync": "",
		"last_deny_sync": "", "next_deny_sync": "",
	}
	macHex        = regexp.MustCompile(`^[0-9A-F]{12}$`)
	startupLogger *log.Logger
)

func startupLog(format string, args ...interface{}) {
	if startupLogger != nil {
		startupLogger.Printf(format, args...)
	}
}

func nowISO() string { return time.Now().Format(time.RFC3339) }

func normalizeMAC(s string) (string, bool) {
	s = strings.ToUpper(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			b.WriteRune(r)
		}
	}
	x := b.String()
	if len(x) != 12 || !macHex.MatchString(x) {
		return "", false
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s-%s", x[0:2], x[2:4], x[4:6], x[6:8], x[8:10], x[10:12]), true
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		d, _ := os.Getwd()
		return d
	}
	return filepath.Dir(p)
}

func loadConfig() error {
	cfg = Config{Listen: "0.0.0.0", Port: 8888, DHCPServer: "localhost", PollIntervalSeconds: 300, DenySyncIntervalSeconds: 14400}
	p := filepath.Join(baseDir, "config.json")
	b, err := os.ReadFile(p)
	if err == nil {
		if e := json.Unmarshal(b, &cfg); e != nil {
			return fmt.Errorf("config.json parse failed: %w", e)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("config.json read failed: %w", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 8888
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	if cfg.DHCPServer == "" {
		cfg.DHCPServer = "localhost"
	}
	if cfg.PollIntervalSeconds < 60 {
		cfg.PollIntervalSeconds = 300
	}
	if cfg.DenySyncIntervalSeconds < 3600 {
		cfg.DenySyncIntervalSeconds = 14400
	}
	return nil
}

func copyFileIfExists(src, dst string) {
	b, err := os.ReadFile(src)
	if err != nil {
		return
	}
	_ = os.WriteFile(dst, b, 0600)
}

func backupDataOnStartup() {
	if _, err := os.Stat(dataPath); err != nil {
		return
	}
	root := filepath.Join(baseDir, "backup")
	dir := filepath.Join(root, time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	copyFileIfExists(dataPath, filepath.Join(dir, filepath.Base(dataPath)))
	copyFileIfExists(filepath.Join(baseDir, "config.json"), filepath.Join(dir, "config.json"))
	entries, err := os.ReadDir(root)
	if err == nil && len(entries) > 30 {
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries[:len(entries)-30] {
			if e.IsDir() {
				_ = os.RemoveAll(filepath.Join(root, e.Name()))
			}
		}
	}
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startupLog("HTTP %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func saveStateLocked() error {
	tmp := dataPath + ".tmp"
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, dataPath)
}

func loadState() error {
	state = Persist{Devices: map[string]*Device{}, Users: map[string]*User{}, Audit: []Audit{}}
	b, err := os.ReadFile(dataPath)
	if err == nil {
		if e := json.Unmarshal(b, &state); e == nil {
			if state.Devices == nil {
				state.Devices = map[string]*Device{}
			}
			if state.Users == nil {
				state.Users = map[string]*User{}
			}
			for _, u := range state.Users {
				u.Role = strings.ToLower(strings.TrimSpace(u.Role))
				if u.Role != "admin" && u.Role != "operator" && u.Role != "viewer" {
					u.Role = "viewer"
				}
			}
			if state.Audit == nil {
				state.Audit = []Audit{}
			}
			if state.RecycleBin == nil {
				state.RecycleBin = []DeletedDevice{}
			}
			for mac, d := range state.Devices {
				if d == nil {
					delete(state.Devices, mac)
					continue
				}
				if d.ActiveLeases == nil {
					d.ActiveLeases = []LeaseSnapshot{}
				}
				if d.OnlineDates == nil {
					d.OnlineDates = []string{}
				}
				if d.MultiLease.Observations == nil {
					d.MultiLease.Observations = []LeaseObservation{}
				}
				if d.MultiLease.StaleIPs == nil {
					d.MultiLease.StaleIPs = []string{}
				}
			}
			return nil
		} else {
			bad := dataPath + ".invalid_" + time.Now().Format("20060102_150405")
			_ = os.WriteFile(bad, b, 0600)
			startupLog("data parse failed; preserved as %s: %v; starting with empty compatible state", bad, e)
			return nil
		}
	}
	// Migrate v1.2 dhcp_devices.json when present. Flexible parser for common array/object layouts.
	legacy := filepath.Join(baseDir, "dhcp_devices.json")
	if lb, e := os.ReadFile(legacy); e == nil {
		var raw interface{}
		if json.Unmarshal(lb, &raw) == nil {
			migrateLegacy(raw)
			_ = saveStateLocked()
		}
	}
	return nil
}

func migrateLegacy(raw interface{}) {
	addObj := func(m map[string]interface{}) {
		macv, _ := m["mac"].(string)
		mac, ok := normalizeMAC(macv)
		if !ok {
			return
		}
		d := &Device{MAC: mac, CreatedAt: nowISO(), CreatedBy: "migration", UpdatedAt: nowISO(), UpdatedBy: "migration"}
		for k, v := range m {
			s := fmt.Sprint(v)
			switch strings.ToLower(k) {
			case "name", "username":
				d.Name = s
			case "note", "description":
				d.Note = s
			case "last_ip", "ip":
				d.LastIP = s
			case "hostname":
				d.Hostname = s
			case "scope", "scope_id":
				d.Scope = s
			case "last_seen":
				d.LastSeen = s
			case "created_at":
				d.CreatedAt = s
			case "updated_at":
				d.UpdatedAt = s
			}
		}
		state.Devices[mac] = d
	}
	switch v := raw.(type) {
	case []interface{}:
		for _, x := range v {
			if m, ok := x.(map[string]interface{}); ok {
				addObj(m)
			}
		}
	case map[string]interface{}:
		if arr, ok := v["devices"].([]interface{}); ok {
			for _, x := range arr {
				if m, ok := x.(map[string]interface{}); ok {
					addObj(m)
				}
			}
			return
		}
		for key, x := range v {
			if m, ok := x.(map[string]interface{}); ok {
				if _, has := m["mac"]; !has {
					m["mac"] = key
				}
				addObj(m)
			}
		}
	}
}

func derivePassword(password string, salt []byte) []byte {
	h := sha256.Sum256(append(append([]byte{}, salt...), []byte(password)...))
	out := h[:]
	for i := 0; i < 120000; i++ {
		x := sha256.Sum256(append(append([]byte{}, out...), salt...))
		out = x[:]
	}
	return out
}

func newPassword(password string) (salt, hash string) {
	s := make([]byte, 16)
	_, _ = rand.Read(s)
	h := derivePassword(password, s)
	return base64.RawStdEncoding.EncodeToString(s), hex.EncodeToString(h)
}
func checkPassword(u *User, password string) bool {
	s, e := base64.RawStdEncoding.DecodeString(u.Salt)
	if e != nil {
		return false
	}
	got := derivePassword(password, s)
	want, e := hex.DecodeString(u.PasswordHash)
	if e != nil || len(want) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return host
	}
	return r.RemoteAddr
}
func addAudit(username, action, mac, detail, ip string) {
	mu.Lock()
	defer mu.Unlock()
	state.Audit = append(state.Audit, Audit{Time: nowISO(), Username: username, Action: action, MAC: mac, Detail: detail, ClientIP: ip})
	if len(state.Audit) > 10000 {
		state.Audit = state.Audit[len(state.Audit)-10000:]
	}
	_ = saveStateLocked()
}

func authUser(r *http.Request) (*User, bool) {
	c, e := r.Cookie("dhcpmon_session")
	if e != nil {
		return nil, false
	}
	sessionMu.Lock()
	sess, ok := sessions[c.Value]
	if ok && time.Now().After(sess.Expires) {
		delete(sessions, c.Value)
		ok = false
	}
	sessionMu.Unlock()
	if !ok {
		return nil, false
	}
	mu.RLock()
	u := state.Users[sess.Username]
	mu.RUnlock()
	if u == nil || !u.Enabled {
		sessionMu.Lock()
		delete(sessions, c.Value)
		sessionMu.Unlock()
		return nil, false
	}
	u.Role = strings.ToLower(strings.TrimSpace(u.Role))
	return u, true
}
func requireAuth(w http.ResponseWriter, r *http.Request) (*User, bool) {
	u, ok := authUser(r)
	if !ok {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			jsonErr(w, "Authentication required", 401)
		} else {
			http.Redirect(w, r, "/login", 302)
		}
		return nil, false
	}
	return u, true
}
func requireAdmin(w http.ResponseWriter, r *http.Request) (*User, bool) {
	u, ok := requireAuth(w, r)
	if !ok {
		return nil, false
	}
	if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
		jsonErr(w, "Admin permission required", 403)
		return nil, false
	}
	return u, true
}
func canEdit(u *User) bool {
	r := strings.ToLower(strings.TrimSpace(u.Role))
	return r == "admin" || r == "operator"
}
func jsonOut(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	jsonOut(w, map[string]interface{}{"error": msg})
}

func psEscape(s string) string { return strings.ReplaceAll(s, "'", "''") }
func runPowerShell(script string) ([]byte, error) {
	prefix := `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $OutputEncoding=[Console]::OutputEncoding; $ErrorActionPreference='Stop'; `
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix+script)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("PowerShell: %v: %s", err, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func runPowerShellInput(script, input string) ([]byte, error) {
	prefix := `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $OutputEncoding=[Console]::OutputEncoding; $ErrorActionPreference='Stop'; `
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix+script)
	cmd.Stdin = strings.NewReader(input)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("PowerShell: %v: %s", err, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func fetchAllow() ([]AllowRow, error) {
	s := psEscape(cfg.DHCPServer)
	script := fmt.Sprintf(`$r=@(Get-DhcpServerv4Filter -ComputerName '%s' -List Allow | ForEach-Object { [pscustomobject]@{mac=$_.MacAddress;note=$_.Description} }); $r | ConvertTo-Json -Compress`, s)
	b, e := runPowerShell(script)
	if e != nil {
		return nil, e
	}
	txt := strings.TrimSpace(string(b))
	if txt == "" || txt == "null" {
		return []AllowRow{}, nil
	}
	var rows []AllowRow
	if strings.HasPrefix(txt, "{") {
		var x AllowRow
		if e = json.Unmarshal([]byte(txt), &x); e == nil {
			rows = []AllowRow{x}
			return rows, nil
		}
	}
	e = json.Unmarshal([]byte(txt), &rows)
	return rows, e
}

func fetchLeases() ([]LeaseRow, error) {
	s := psEscape(cfg.DHCPServer)
	script := fmt.Sprintf(`$rows=@(Get-DhcpServerv4Scope -ComputerName '%s' | ForEach-Object { $sid=$_.ScopeId.IPAddressToString; Get-DhcpServerv4Lease -ComputerName '%s' -ScopeId $_.ScopeId | ForEach-Object { $exp=''; if($_.LeaseExpiryTime){$exp=$_.LeaseExpiryTime.ToUniversalTime().ToString('o')}; [pscustomobject]@{mac=$_.ClientId;ip=$_.IPAddress.IPAddressToString;hostname=$_.HostName;scope=$sid;address_state=[string]$_.AddressState;lease_expiry=$exp} } }); $rows | ConvertTo-Json -Compress`, s, s)
	b, e := runPowerShell(script)
	if e != nil {
		return nil, e
	}
	txt := strings.TrimSpace(string(b))
	if txt == "" || txt == "null" {
		return []LeaseRow{}, nil
	}
	var rows []LeaseRow
	if strings.HasPrefix(txt, "{") {
		var x LeaseRow
		if e = json.Unmarshal([]byte(txt), &x); e == nil {
			rows = []LeaseRow{x}
			return rows, nil
		}
	}
	e = json.Unmarshal([]byte(txt), &rows)
	return rows, e
}

func fetchDeny() ([]AllowRow, error) {
	s := psEscape(cfg.DHCPServer)
	script := fmt.Sprintf(`$r=@(Get-DhcpServerv4Filter -ComputerName '%s' -List Deny | ForEach-Object { [pscustomobject]@{mac=$_.MacAddress;note=$_.Description} }); $r | ConvertTo-Json -Compress`, s)
	b, e := runPowerShell(script)
	if e != nil {
		return nil, e
	}
	txt := strings.TrimSpace(string(b))
	if txt == "" || txt == "null" {
		return []AllowRow{}, nil
	}
	var rows []AllowRow
	if strings.HasPrefix(txt, "{") {
		var x AllowRow
		if e = json.Unmarshal([]byte(txt), &x); e == nil {
			return []AllowRow{x}, nil
		}
	}
	e = json.Unmarshal([]byte(txt), &rows)
	return rows, e
}

func addAllow(mac, note string) error { return setFilterState(mac, note, "Allow") }
func addDeny(mac, note string) error  { return setFilterState(mac, note, "Deny") }

// Remove-DhcpServerv4Filter does NOT have a -List parameter. It removes the MAC
// from whichever DHCP filter list currently contains it.
func removeFilter(mac string) error {
	_, e := runPowerShell(fmt.Sprintf(`Remove-DhcpServerv4Filter -ComputerName '%s' -MacAddress '%s' -Confirm:$false -ErrorAction SilentlyContinue`, psEscape(cfg.DHCPServer), psEscape(mac)))
	return e
}

// setFilterState moves a MAC to exactly one target list. It records the previous
// DHCP state inside PowerShell and restores it if the target write fails.
func setFilterState(mac, note, target string) error {
	if target != "Allow" && target != "Deny" {
		return fmt.Errorf("invalid DHCP filter target")
	}
	server := psEscape(cfg.DHCPServer)
	m := psEscape(mac)
	n := psEscape(note)
	script := fmt.Sprintf(`
$server='%s'; $mac='%s'; $note='%s'; $target='%s';
$oldAllow=@(Get-DhcpServerv4Filter -ComputerName $server -List Allow | Where-Object { [string]$_.MacAddress -eq $mac });
$oldDeny=@(Get-DhcpServerv4Filter -ComputerName $server -List Deny | Where-Object { [string]$_.MacAddress -eq $mac });
try {
  Remove-DhcpServerv4Filter -ComputerName $server -MacAddress $mac -Confirm:$false -ErrorAction SilentlyContinue;
  Add-DhcpServerv4Filter -ComputerName $server -List $target -MacAddress $mac -Description $note -Force;
} catch {
  $msg=$_.Exception.Message;
  try {
    Remove-DhcpServerv4Filter -ComputerName $server -MacAddress $mac -Confirm:$false -ErrorAction SilentlyContinue;
    if($oldAllow.Count -gt 0){ Add-DhcpServerv4Filter -ComputerName $server -List Allow -MacAddress $mac -Description ([string]$oldAllow[0].Description) -Force }
    elseif($oldDeny.Count -gt 0){ Add-DhcpServerv4Filter -ComputerName $server -List Deny -MacAddress $mac -Description ([string]$oldDeny[0].Description) -Force }
  } catch {}
  throw $msg;
}`, server, m, n, target)
	_, e := runPowerShell(script)
	return e
}

type filterMoveItem struct {
	MAC  string `json:"mac"`
	Note string `json:"note"`
}

type filterMoveResult struct {
	MAC   string `json:"mac"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func moveFiltersToDeny(items []filterMoveItem) ([]filterMoveResult, error) {
	if len(items) == 0 {
		return []filterMoveResult{}, nil
	}
	payload, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	script := fmt.Sprintf(`
$server='%s';
$items=@([Console]::In.ReadToEnd() | ConvertFrom-Json);
$results=@();
foreach($item in $items){
  $mac=[string]$item.mac; $note=[string]$item.note;
  $oldAllow=@(Get-DhcpServerv4Filter -ComputerName $server -List Allow | Where-Object { [string]$_.MacAddress -eq $mac });
  $oldDeny=@(Get-DhcpServerv4Filter -ComputerName $server -List Deny | Where-Object { [string]$_.MacAddress -eq $mac });
  try {
    Remove-DhcpServerv4Filter -ComputerName $server -MacAddress $mac -Confirm:$false -ErrorAction SilentlyContinue;
    Add-DhcpServerv4Filter -ComputerName $server -List Deny -MacAddress $mac -Description $note -Force;
    $results += [pscustomobject]@{mac=$mac;ok=$true;error=''};
  } catch {
    $msg=$_.Exception.Message;
    try {
      Remove-DhcpServerv4Filter -ComputerName $server -MacAddress $mac -Confirm:$false -ErrorAction SilentlyContinue;
      if($oldAllow.Count -gt 0){ Add-DhcpServerv4Filter -ComputerName $server -List Allow -MacAddress $mac -Description ([string]$oldAllow[0].Description) -Force }
      elseif($oldDeny.Count -gt 0){ Add-DhcpServerv4Filter -ComputerName $server -List Deny -MacAddress $mac -Description ([string]$oldDeny[0].Description) -Force }
    } catch { $msg += '; rollback failed: '+$_.Exception.Message }
    $results += [pscustomobject]@{mac=$mac;ok=$false;error=$msg};
  }
}
@($results) | ConvertTo-Json -Compress`, psEscape(cfg.DHCPServer))
	b, err := runPowerShellInput(script, string(payload))
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(b))
	if text == "" || text == "null" {
		return nil, fmt.Errorf("DHCP batch operation returned no result")
	}
	var results []filterMoveResult
	if strings.HasPrefix(text, "{") {
		var one filterMoveResult
		if err := json.Unmarshal([]byte(text), &one); err != nil {
			return nil, err
		}
		return []filterMoveResult{one}, nil
	}
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		return nil, err
	}
	return results, nil
}

func updateSyncFields(values map[string]interface{}) {
	lastSyncMu.Lock()
	for k, v := range values {
		lastSync[k] = v
	}
	lastSyncMu.Unlock()
}

func setNextLeaseDue(t time.Time) {
	scheduleMu.Lock()
	nextLeaseDue = t
	scheduleMu.Unlock()
}

func setNextDenyDue(t time.Time) {
	scheduleMu.Lock()
	nextDenyDue = t
	scheduleMu.Unlock()
}

func getDueTimes() (time.Time, time.Time) {
	scheduleMu.RLock()
	defer scheduleMu.RUnlock()
	return nextLeaseDue, nextDenyDue
}

func parseLeaseExpiry(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t
	}
	return time.Time{}
}

func leaseIsActive(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "" || strings.HasPrefix(v, "active")
}

func addOnlineDate(d *Device, now time.Time) {
	day := now.Format("2006-01-02")
	for _, x := range d.OnlineDates {
		if x == day {
			return
		}
	}
	d.OnlineDates = append(d.OnlineDates, day)
	if len(d.OnlineDates) > 3660 {
		d.OnlineDates = d.OnlineDates[len(d.OnlineDates)-3660:]
	}
}

func pingIP(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	c := exec.Command("ping", "-n", "2", "-w", "1000", ip)
	return c.Run() == nil
}

func releaseLease(scope, ip string) error {
	if net.ParseIP(scope) == nil || net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid scope or IP")
	}
	s := strings.ReplaceAll(cfg.DHCPServer, "'", "''")
	script := fmt.Sprintf("Remove-DhcpServerv4Lease -ComputerName '%s' -ScopeId '%s' -IPAddress '%s' -Confirm:$false -ErrorAction Stop", s, scope, ip)
	_, err := runPowerShell(script)
	return err
}

func inspectMultiLease(d *Device, rows []LeaseRow, now time.Time) (released []string) {
	if len(rows) < 2 {
		d.MultiLease = MultiLeaseState{}
		return nil
	}
	if n := len(d.MultiLease.Observations); n > 0 {
		if last, e := time.Parse(time.RFC3339, d.MultiLease.Observations[n-1].Time); e == nil && now.Sub(last) < 30*time.Minute {
			return nil
		}
	}
	reachable := []LeaseRow{}
	for _, r := range rows {
		if pingIP(r.IP) {
			reachable = append(reachable, r)
		}
	}
	if len(reachable) != 1 {
		return nil
	}
	cur := reachable[0]
	obs := LeaseObservation{Time: now.Format(time.RFC3339), ReachableIP: cur.IP, Scope: cur.Scope}
	ms := &d.MultiLease
	if ms.FirstSeen == "" {
		ms.FirstSeen = obs.Time
	}
	if n := len(ms.Observations); n > 0 && ms.Observations[n-1].Scope != obs.Scope {
		ms.Switches++
	}
	ms.Observations = append(ms.Observations, obs)
	if len(ms.Observations) > 20 {
		ms.Observations = ms.Observations[len(ms.Observations)-20:]
	}
	if len(ms.Observations) >= 3 && ms.Switches >= 2 {
		ms.Mobile = true
		ms.CandidateIP = ""
		ms.StaleIPs = nil
		return nil
	}
	if ms.Mobile {
		return nil
	}
	stale := []string{}
	for _, r := range rows {
		if r.IP != cur.IP {
			stale = append(stale, r.IP)
		}
	}
	first, _ := time.Parse(time.RFC3339, ms.FirstSeen)
	if ms.CandidateIP == cur.IP && strings.Join(ms.StaleIPs, ",") == strings.Join(stale, ",") && now.Sub(first) >= 30*time.Minute {
		for _, r := range rows {
			if r.IP != cur.IP {
				if err := releaseLease(r.Scope, r.IP); err == nil {
					released = append(released, r.IP)
				} else {
					startupLog("multi-lease release failed mac=%s ip=%s: %v", d.MAC, r.IP, err)
				}
			}
		}
		ms.FirstSeen = now.Format(time.RFC3339)
		ms.StaleIPs = nil
	} else if ms.CandidateIP != cur.IP || strings.Join(ms.StaleIPs, ",") != strings.Join(stale, ",") {
		ms.FirstSeen = now.Format(time.RFC3339)
		ms.CandidateIP = cur.IP
		ms.StaleIPs = stale
	}
	return released
}

func syncLeasesOnly() map[string]interface{} {
	started := time.Now()
	leases, le := fetchLeases()
	now := time.Now()
	next := now.Add(time.Duration(cfg.PollIntervalSeconds) * time.Second)
	setNextLeaseDue(next)
	if le != nil {
		res := map[string]interface{}{
			"time": nowISO(), "ok": false, "message": "Lease read failed: " + le.Error(),
			"last_lease_check":  now.Format(time.RFC3339),
			"next_lease_check":  next.Format(time.RFC3339),
			"lease_duration_ms": time.Since(started).Milliseconds(),
		}
		updateSyncFields(res)
		return res
	}

	// A MAC can have active leases in more than one scope. Keep every active
	// lease and select the one with the newest LeaseExpiryTime for display.
	leaseGroups := map[string][]LeaseRow{}
	for _, l := range leases {
		m, ok := normalizeMAC(l.MAC)
		if !ok || !leaseIsActive(l.AddressState) {
			continue
		}
		leaseGroups[m] = append(leaseGroups[m], l)
	}
	for m := range leaseGroups {
		sort.SliceStable(leaseGroups[m], func(i, j int) bool {
			a := parseLeaseExpiry(leaseGroups[m][i].LeaseExpiry)
			b := parseLeaseExpiry(leaseGroups[m][j].LeaseExpiry)
			if !a.Equal(b) {
				return a.After(b)
			}
			if leaseGroups[m][i].Scope != leaseGroups[m][j].Scope {
				return leaseGroups[m][i].Scope < leaseGroups[m][j].Scope
			}
			return leaseGroups[m][i].IP < leaseGroups[m][j].IP
		})
	}

	matched := 0
	multiLeaseMACs := 0
	onlineCount := 0
	offlineTransitions := 0
	stamp := now.Format(time.RFC3339)
	type multiTask struct {
		mac    string
		device Device
		rows   []LeaseRow
	}
	type multiResult struct {
		mac      string
		state    MultiLeaseState
		released []string
	}
	multiTasks := []multiTask{}
	mu.Lock()
	for m, d := range state.Devices {
		rows := leaseGroups[m]
		if len(rows) == 0 {
			d.ActiveLeaseCount = 0
			d.ActiveLeases = nil
			if d.Disabled {
				d.IsOnline = false
				d.OnlineSince = ""
				d.MissedChecks = 0
				continue
			}
			if d.IsOnline {
				d.MissedChecks++
				// Two consecutive missed 5-minute checks are required before the
				// current session is closed. This avoids a one-scan transient from
				// immediately changing the status to offline.
				if d.MissedChecks >= 2 {
					d.IsOnline = false
					d.OnlineSince = ""
					d.LastOfflineAt = stamp
					d.MissedChecks = 0
					offlineTransitions++
				}
			} else {
				d.MissedChecks = 0
			}
			continue
		}

		matched++
		if len(rows) > 1 {
			multiLeaseMACs++
		}
		chosen := rows[0]

		if !d.Disabled {
			if !d.IsOnline || d.OnlineSince == "" {
				d.IsOnline = true
				d.OnlineSince = stamp
			}
			d.MissedChecks = 0
			d.LastSeen = stamp
			addOnlineDate(d, now)
			onlineCount++
		} else {
			d.IsOnline = false
			d.OnlineSince = ""
			d.MissedChecks = 0
		}

		d.LastIP = chosen.IP
		d.Hostname = chosen.Hostname
		d.Scope = chosen.Scope
		d.LastLeaseExpiry = chosen.LeaseExpiry
		d.ActiveLeaseCount = len(rows)
		d.ActiveLeases = make([]LeaseSnapshot, 0, len(rows))
		for _, l := range rows {
			d.ActiveLeases = append(d.ActiveLeases, LeaseSnapshot{IP: l.IP, Hostname: l.Hostname, Scope: l.Scope, AddressState: l.AddressState, LeaseExpiry: l.LeaseExpiry})
		}
		if len(rows) > 1 {
			copyDevice := *d
			copyDevice.MultiLease.Observations = append([]LeaseObservation(nil), d.MultiLease.Observations...)
			copyDevice.MultiLease.StaleIPs = append([]string(nil), d.MultiLease.StaleIPs...)
			multiTasks = append(multiTasks, multiTask{mac: m, device: copyDevice, rows: append([]LeaseRow(nil), rows...)})
		}
	}
	_ = saveStateLocked()
	mu.Unlock()
	// Ping and DHCP release operations may take seconds per address. They must
	// never hold the global state lock, otherwise login/dashboard requests stall.
	multiResults := make([]multiResult, 0, len(multiTasks))
	for _, task := range multiTasks {
		released := inspectMultiLease(&task.device, task.rows, now)
		multiResults = append(multiResults, multiResult{mac: task.mac, state: task.device.MultiLease, released: released})
	}
	if len(multiResults) > 0 {
		mu.Lock()
		for _, x := range multiResults {
			if d := state.Devices[x.mac]; d != nil {
				d.MultiLease = x.state
				if len(x.released) > 0 {
					state.Audit = append(state.Audit, Audit{Time: stamp, Username: "system", Action: "release_stale_lease", MAC: x.mac, Detail: "Released after two clear checks 30 minutes apart: " + strings.Join(x.released, ","), ClientIP: "local"})
				}
			}
		}
		_ = saveStateLocked()
		mu.Unlock()
	}
	res := map[string]interface{}{
		"time": stamp, "ok": true,
		"message":             fmt.Sprintf("Lease check complete: %d leases, %d managed MACs matched, %d currently online, %d went offline, %d MACs have multiple active leases", len(leases), matched, onlineCount, offlineTransitions, multiLeaseMACs),
		"last_lease_check":    stamp,
		"next_lease_check":    next.Format(time.RFC3339),
		"lease_duration_ms":   time.Since(started).Milliseconds(),
		"lease_count":         len(leases),
		"matched_count":       matched,
		"online_count":        onlineCount,
		"offline_transitions": offlineTransitions,
		"multi_lease_macs":    multiLeaseMACs,
	}
	updateSyncFields(res)
	return res
}

func reconcileFilterRows(allows, denies []AllowRow, includeAllow, includeDeny bool) (int, int) {
	now := nowISO()
	auditRows := []Audit{}
	allowCount, denyCount := 0, 0
	mu.Lock()
	if includeAllow {
		for _, a := range allows {
			m, ok := normalizeMAC(a.MAC)
			if !ok {
				continue
			}
			allowCount++
			d := state.Devices[m]
			if d == nil {
				d = &Device{MAC: m, CreatedAt: now, CreatedBy: "dhcp-import"}
				state.Devices[m] = d
				auditRows = append(auditRows, Audit{Time: now, Username: "system", Action: "sync_add_mac", MAC: m, Detail: "Detected MAC in Windows DHCP Allow", ClientIP: "local"})
			}
			if d.Disabled {
				d.Disabled = false
				d.IsOnline = false
				d.OnlineSince = ""
				d.MissedChecks = 0
				auditRows = append(auditRows, Audit{Time: now, Username: "system", Action: "sync_enable_mac", MAC: m, Detail: "Detected MAC in DHCP Allow; local status changed to enabled", ClientIP: "local"})
			}
			if d.Note != a.Note {
				old := d.Note
				d.Note = a.Note
				auditRows = append(auditRows, Audit{Time: now, Username: "system", Action: "sync_update_mac", MAC: m, Detail: fmt.Sprintf("Allow Description: %q -> %q", old, a.Note), ClientIP: "local"})
			}
			d.UpdatedAt = now
			d.UpdatedBy = "dhcp-sync"
		}
	}
	if includeDeny {
		for _, a := range denies {
			m, ok := normalizeMAC(a.MAC)
			if !ok {
				continue
			}
			denyCount++
			d := state.Devices[m]
			if d == nil {
				d = &Device{MAC: m, CreatedAt: now, CreatedBy: "dhcp-import", Disabled: true}
				state.Devices[m] = d
				auditRows = append(auditRows, Audit{Time: now, Username: "system", Action: "sync_add_deny_mac", MAC: m, Detail: "Detected MAC in Windows DHCP Deny", ClientIP: "local"})
			}
			if !d.Disabled {
				d.Disabled = true
				d.IsOnline = false
				d.OnlineSince = ""
				d.MissedChecks = 0
				d.LastOfflineAt = now
				auditRows = append(auditRows, Audit{Time: now, Username: "system", Action: "sync_disable_mac", MAC: m, Detail: "Detected MAC in DHCP Deny; local status changed to disabled", ClientIP: "local"})
			}
			if d.Note != a.Note {
				old := d.Note
				d.Note = a.Note
				auditRows = append(auditRows, Audit{Time: now, Username: "system", Action: "sync_update_deny_mac", MAC: m, Detail: fmt.Sprintf("Deny Description: %q -> %q", old, a.Note), ClientIP: "local"})
			}
			d.UpdatedAt = now
			d.UpdatedBy = "dhcp-sync"
		}
	}
	state.Audit = append(state.Audit, auditRows...)
	if len(state.Audit) > 10000 {
		state.Audit = state.Audit[len(state.Audit)-10000:]
	}
	_ = saveStateLocked()
	mu.Unlock()
	return allowCount, denyCount
}

func syncDenyOnly() map[string]interface{} {
	started := time.Now()
	denies, err := fetchDeny()
	now := time.Now()
	next := now.Add(time.Duration(cfg.DenySyncIntervalSeconds) * time.Second)
	setNextDenyDue(next)
	if err != nil {
		res := map[string]interface{}{
			"time": nowISO(), "ok": false, "message": "Deny read failed: " + err.Error(),
			"last_deny_sync": now.Format(time.RFC3339),
			"next_deny_sync": next.Format(time.RFC3339),
		}
		updateSyncFields(res)
		return res
	}
	_, denyCount := reconcileFilterRows(nil, denies, false, true)
	stamp := now.Format(time.RFC3339)
	res := map[string]interface{}{
		"time": stamp, "ok": true,
		"message":          fmt.Sprintf("Deny sync complete: %d MACs", denyCount),
		"last_deny_sync":   stamp,
		"next_deny_sync":   now.Add(time.Duration(cfg.DenySyncIntervalSeconds) * time.Second).Format(time.RFC3339),
		"deny_count":       denyCount,
		"deny_duration_ms": time.Since(started).Milliseconds(),
	}
	updateSyncFields(res)
	return res
}

func syncDHCP() map[string]interface{} {
	started := time.Now()
	allows, ae := fetchAllow()
	if ae != nil {
		res := map[string]interface{}{"time": nowISO(), "ok": false, "message": "Allow read failed: " + ae.Error()}
		updateSyncFields(res)
		return res
	}
	denies, de := fetchDeny()
	if de != nil {
		res := map[string]interface{}{"time": nowISO(), "ok": false, "message": "Deny read failed: " + de.Error()}
		updateSyncFields(res)
		return res
	}
	allowCount, denyCount := reconcileFilterRows(allows, denies, true, true)
	stamp := nowISO()
	denyNext := time.Now().Add(time.Duration(cfg.DenySyncIntervalSeconds) * time.Second)
	setNextDenyDue(denyNext)
	updateSyncFields(map[string]interface{}{
		"last_allow_sync": stamp,
		"last_deny_sync":  stamp,
		"next_deny_sync":  denyNext.Format(time.RFC3339),
		"allow_mode":      "realtime",
		"allow_count":     allowCount,
		"deny_count":      denyCount,
	})
	leaseRes := syncLeasesOnly()
	ok, _ := leaseRes["ok"].(bool)
	msg := fmt.Sprintf("Full sync complete: %d Allow, %d Deny", allowCount, denyCount)
	if ok {
		msg += fmt.Sprintf(", %v leases, %v matched", leaseRes["lease_count"], leaseRes["matched_count"])
	} else {
		msg += "; " + fmt.Sprint(leaseRes["message"])
	}
	res := map[string]interface{}{
		"time": nowISO(), "ok": ok, "message": msg,
		"allow_count": allowCount, "deny_count": denyCount,
		"lease_count": leaseRes["lease_count"], "matched_count": leaseRes["matched_count"],
		"full_sync_duration_ms": time.Since(started).Milliseconds(),
	}
	updateSyncFields(res)
	return res
}

func statusOf(d *Device) (string, float64) {
	if d.Disabled {
		return "disabled", -1
	}
	if d.IsOnline {
		days := float64(len(d.OnlineDates))
		if days >= 7 {
			return "over7", days
		}
		if days >= 3 {
			return "over3", days
		}
		return "normal", days
	}
	if d.LastSeen == "" {
		return "never", -1
	}
	t, e := time.Parse(time.RFC3339, d.LastSeen)
	if e != nil {
		return "never", -1
	}
	elapsed := time.Now().Truncate(time.Second).Sub(t)
	if elapsed < 0 {
		elapsed = 0
	}
	days := elapsed.Hours() / 24
	return "offline", days
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := authUser(r); ok {
		http.Redirect(w, r, "/", 302)
		return
	}
	mu.RLock()
	first := len(state.Users) == 0
	mu.RUnlock()
	if first {
		http.Redirect(w, r, "/setup", 302)
		return
	}
	if r.Method == "POST" {
		_ = r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		mu.RLock()
		u := state.Users[user]
		mu.RUnlock()
		if u != nil && u.Enabled && checkPassword(u, pass) {
			token := randToken()
			sessionMu.Lock()
			sessions[token] = Session{Username: user, Expires: time.Now().Add(12 * time.Hour)}
			sessionMu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "dhcpmon_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
			addAudit(user, "login", "", "Successful login", clientIP(r))
			http.Redirect(w, r, "/", 302)
			return
		}
		addAudit(user, "login_failed", "", "Failed login", clientIP(r))
		renderLogin(w, "Invalid username or password")
		return
	}
	renderLogin(w, "")
}
func renderLogin(w http.ResponseWriter, msg string) {
	_ = loginTpl.Execute(w, map[string]string{"Msg": msg})
}
func setupPage(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	has := len(state.Users) > 0
	mu.RUnlock()
	if has {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method == "POST" {
		_ = r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		if len(user) < 3 || len(pass) < 8 {
			_ = setupTpl.Execute(w, map[string]string{"Msg": "Username >= 3 chars; password >= 8 chars"})
			return
		}
		salt, hash := newPassword(pass)
		mu.Lock()
		state.Users[user] = &User{Username: user, Role: "admin", Salt: salt, PasswordHash: hash, CreatedAt: nowISO(), CreatedBy: "setup", Enabled: true}
		_ = saveStateLocked()
		mu.Unlock()
		addAudit(user, "setup_admin", "", "Initial admin created", clientIP(r))
		http.Redirect(w, r, "/login", 302)
		return
	}
	_ = setupTpl.Execute(w, map[string]string{"Msg": ""})
}
func logout(w http.ResponseWriter, r *http.Request) {
	if u, ok := authUser(r); ok {
		addAudit(u.Username, "logout", "", "Logged out", clientIP(r))
	}
	if c, e := r.Cookie("dhcpmon_session"); e == nil {
		sessionMu.Lock()
		delete(sessions, c.Value)
		sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "dhcpmon_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", 302)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	_ = dashboardTpl.Execute(w, map[string]interface{}{
		"Username": template.HTMLEscapeString(u.Username),
		"Role":     template.HTMLEscapeString(u.Role),
		"IsAdmin":  strings.EqualFold(strings.TrimSpace(u.Role), "admin"),
		"CanEdit":  canEdit(u),
	})
}

func apiDevices(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	_ = u
	mu.RLock()
	arr := make([]map[string]interface{}, 0, len(state.Devices))
	for _, d := range state.Devices {
		st, days := statusOf(d)
		arr = append(arr, map[string]interface{}{"mac": d.MAC, "name": d.Name, "note": d.Note, "last_ip": d.LastIP, "hostname": d.Hostname, "scope": d.Scope, "last_seen": d.LastSeen, "last_detected": d.LastSeen, "online_since": d.OnlineSince, "is_online": d.IsOnline, "missed_checks": d.MissedChecks, "last_offline_at": d.LastOfflineAt, "last_lease_expiry": d.LastLeaseExpiry, "active_lease_count": d.ActiveLeaseCount, "active_leases": d.ActiveLeases, "reservation": d.Reservation, "multi_lease": d.MultiLease, "created_at": d.CreatedAt, "created_by": d.CreatedBy, "updated_at": d.UpdatedAt, "updated_by": d.UpdatedBy, "status": st, "days": days, "enabled": !d.Disabled})
	}
	mu.RUnlock()
	sort.SliceStable(arr, func(i, j int) bool {
		a, b := arr[i], arr[j]
		rank := func(v map[string]interface{}) int {
			switch v["status"].(string) {
			case "over7":
				return 0
			case "over3":
				return 1
			case "normal":
				return 2
			case "disabled":
				return 3
			case "offline":
				return 4
			default:
				return 5
			}
		}
		ra, rb := rank(a), rank(b)
		if ra != rb {
			return ra < rb
		}
		var ta, tb string
		if a["days"].(float64) != b["days"].(float64) {
			return a["days"].(float64) > b["days"].(float64)
		}
		if ra <= 2 {
			ta, tb = a["online_since"].(string), b["online_since"].(string)
		} else {
			ta, tb = a["last_detected"].(string), b["last_detected"].(string)
			if ta != tb {
				return ta > tb
			}
		}
		return a["mac"].(string) < b["mac"].(string)
	})
	lastSyncMu.RLock()
	ls := lastSync
	lastSyncMu.RUnlock()
	jsonOut(w, map[string]interface{}{"devices": arr, "sync": ls, "user": map[string]string{"username": u.Username, "role": u.Role}})
}

func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}
func apiAdd(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !canEdit(u) {
		jsonErr(w, "Read-only account", 403)
		return
	}
	var q struct{ MAC, Name, Note string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	mac, ok := normalizeMAC(q.MAC)
	if !ok {
		jsonErr(w, "Invalid MAC address", 400)
		return
	}
	q.Name = strings.TrimSpace(q.Name)
	q.Note = strings.TrimSpace(q.Note)
	mu.RLock()
	_, exists := state.Devices[mac]
	mu.RUnlock()
	if exists {
		mu.RLock()
		old := state.Devices[mac]
		mu.RUnlock()
		if old.Disabled {
			if err := addAllow(mac, q.Note); err != nil {
				jsonErr(w, err.Error(), 500)
				return
			}
			mu.Lock()
			old.Disabled = false
			old.Name = q.Name
			old.Note = q.Note
			old.UpdatedAt = nowISO()
			old.UpdatedBy = u.Username
			_ = saveStateLocked()
			mu.Unlock()
			addAudit(u.Username, "restore_deny_to_allow", mac, "Existing Deny MAC enabled and details updated", clientIP(r))
			jsonOut(w, map[string]interface{}{"ok": true, "mac": mac, "restored": true})
			return
		}
		jsonErr(w, "MAC already exists", 409)
		return
	}
	if err := addAllow(mac, q.Note); err != nil {
		addAudit(u.Username, "add_mac_failed", mac, "DHCP Allow write failed: "+err.Error(), clientIP(r))
		jsonErr(w, err.Error(), 500)
		return
	}
	now := nowISO()
	mu.Lock()
	state.Devices[mac] = &Device{MAC: mac, Name: q.Name, Note: q.Note, CreatedAt: now, CreatedBy: u.Username, UpdatedAt: now, UpdatedBy: u.Username}
	_ = saveStateLocked()
	mu.Unlock()
	updateSyncFields(map[string]interface{}{"last_allow_sync": now, "allow_mode": "realtime"})
	addAudit(u.Username, "add_mac", mac, fmt.Sprintf("Added to DHCP Allow; name=%q; note=%q", q.Name, q.Note), clientIP(r))
	jsonOut(w, map[string]interface{}{"ok": true, "mac": mac})
}
func apiUpdate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !canEdit(u) {
		jsonErr(w, "Read-only account", 403)
		return
	}
	var q struct{ MAC, Name, Note string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	mac, ok := normalizeMAC(q.MAC)
	if !ok {
		jsonErr(w, "Invalid MAC address", 400)
		return
	}
	q.Name = strings.TrimSpace(q.Name)
	q.Note = strings.TrimSpace(q.Note)
	mu.RLock()
	d0 := state.Devices[mac]
	mu.RUnlock()
	if d0 == nil {
		jsonErr(w, "MAC not found", 404)
		return
	}
	oldName, oldNote, disabled := d0.Name, d0.Note, d0.Disabled
	var err error
	if disabled {
		err = addDeny(mac, q.Note)
	} else {
		err = addAllow(mac, q.Note)
	}
	if err != nil {
		addAudit(u.Username, "update_mac_failed", mac, "DHCP filter update failed: "+err.Error(), clientIP(r))
		jsonErr(w, err.Error(), 500)
		return
	}
	now := nowISO()
	mu.Lock()
	d := state.Devices[mac]
	d.Name = q.Name
	d.Note = q.Note
	d.UpdatedAt = now
	d.UpdatedBy = u.Username
	_ = saveStateLocked()
	mu.Unlock()
	if disabled {
		updateSyncFields(map[string]interface{}{"last_deny_sync": now})
	} else {
		updateSyncFields(map[string]interface{}{"last_allow_sync": now, "allow_mode": "realtime"})
	}
	addAudit(u.Username, "update_mac", mac, fmt.Sprintf("Name %q -> %q; note %q -> %q; list=%s", oldName, q.Name, oldNote, q.Note, map[bool]string{true: "Deny", false: "Allow"}[disabled]), clientIP(r))
	jsonOut(w, map[string]interface{}{"ok": true, "mac": mac})
}
func apiDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct{ MAC string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	mac, ok := normalizeMAC(q.MAC)
	if !ok {
		jsonErr(w, "Invalid MAC", 400)
		return
	}
	mu.RLock()
	d0 := state.Devices[mac]
	mu.RUnlock()
	if d0 == nil {
		jsonErr(w, "MAC not found", 404)
		return
	}
	before := fmt.Sprintf("name=%q note=%q disabled=%v created_by=%q", d0.Name, d0.Note, d0.Disabled, d0.CreatedBy)
	if err := removeFilter(mac); err != nil {
		addAudit(u.Username, "delete_mac_failed", mac, "DHCP remove failed: "+err.Error(), clientIP(r))
		jsonErr(w, err.Error(), 500)
		return
	}
	mu.Lock()
	snap := *d0
	snap.ActiveLeases = append([]LeaseSnapshot(nil), d0.ActiveLeases...)
	snap.OnlineDates = append([]string(nil), d0.OnlineDates...)
	state.RecycleBin = append(state.RecycleBin, DeletedDevice{DeletedAt: nowISO(), DeletedBy: u.Username, Reason: "single delete", Snapshot: snap})
	delete(state.Devices, mac)
	_ = saveStateLocked()
	mu.Unlock()
	now := nowISO()
	updateSyncFields(map[string]interface{}{"last_allow_sync": now, "last_deny_sync": now})
	addAudit(u.Username, "delete_mac", mac, "Deleted from DHCP filter and local database; before: "+before, clientIP(r))
	jsonOut(w, map[string]bool{"ok": true})
}

func apiBulkDeleteDisabled(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, "Method not allowed", 405)
		return
	}
	mu.RLock()
	macs := []string{}
	for m, d := range state.Devices {
		if d.Disabled {
			macs = append(macs, m)
		}
	}
	mu.RUnlock()
	sort.Strings(macs)
	success := 0
	failed := []string{}
	for _, m := range macs {
		mu.RLock()
		d := state.Devices[m]
		mu.RUnlock()
		if d == nil {
			continue
		}
		if err := removeFilter(m); err != nil {
			failed = append(failed, m+": "+err.Error())
			addAudit(u.Username, "bulk_delete_disabled_failed", m, err.Error(), clientIP(r))
			continue
		}
		mu.Lock()
		snap := *d
		snap.ActiveLeases = append([]LeaseSnapshot(nil), d.ActiveLeases...)
		state.RecycleBin = append(state.RecycleBin, DeletedDevice{DeletedAt: nowISO(), DeletedBy: u.Username, Reason: "bulk disabled delete", Snapshot: snap})
		delete(state.Devices, m)
		state.Audit = append(state.Audit, Audit{Time: nowISO(), Username: u.Username, Action: "bulk_delete_disabled", MAC: m, Detail: "Full snapshot saved to recycle bin", ClientIP: clientIP(r)})
		_ = saveStateLocked()
		mu.Unlock()
		success++
	}
	jsonOut(w, map[string]interface{}{"ok": len(failed) == 0, "success": success, "failed": failed})
}

func apiRecycle(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	mu.RLock()
	defer mu.RUnlock()
	jsonOut(w, map[string]interface{}{"items": state.RecycleBin, "user": u.Username})
}
func apiRecycleRestore(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct{ MAC string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	m, ok := normalizeMAC(q.MAC)
	if !ok {
		jsonErr(w, "Invalid MAC", 400)
		return
	}
	mu.RLock()
	idx := -1
	var x DeletedDevice
	for i := len(state.RecycleBin) - 1; i >= 0; i-- {
		if state.RecycleBin[i].Snapshot.MAC == m {
			idx = i
			x = state.RecycleBin[i]
			break
		}
	}
	_, exists := state.Devices[m]
	mu.RUnlock()
	if idx < 0 {
		jsonErr(w, "Not found in recycle bin", 404)
		return
	}
	if exists {
		jsonErr(w, "MAC already exists", 409)
		return
	}
	if x.Snapshot.Disabled {
		if err := addDeny(m, x.Snapshot.Note); err != nil {
			jsonErr(w, err.Error(), 500)
			return
		}
	} else {
		if err := addAllow(m, x.Snapshot.Note); err != nil {
			jsonErr(w, err.Error(), 500)
			return
		}
	}
	reservationRestored := false
	if x.Snapshot.Reservation != nil {
		if err := createReservation(m, *x.Snapshot.Reservation); err == nil {
			reservationRestored = true
		} else {
			startupLog("reservation restore skipped mac=%s: %v", m, err)
		}
	}
	mu.Lock()
	d := x.Snapshot
	if d.Reservation != nil && !reservationRestored {
		d.Reservation = nil
	}
	state.Devices[m] = &d
	state.RecycleBin = append(state.RecycleBin[:idx], state.RecycleBin[idx+1:]...)
	_ = saveStateLocked()
	mu.Unlock()
	addAudit(u.Username, "recover_deleted_mac", m, fmt.Sprintf("Restored full snapshot; reservation_restored=%v", reservationRestored), clientIP(r))
	jsonOut(w, map[string]interface{}{"ok": true, "reservation_restored": reservationRestored})
}

func createReservation(mac string, r Reservation) error {
	if net.ParseIP(r.IP) == nil || net.ParseIP(r.Scope) == nil {
		return fmt.Errorf("invalid IP or Scope")
	}
	s := psEscape(cfg.DHCPServer)
	script := fmt.Sprintf(`$scope=Get-DhcpServerv4Scope -ComputerName '%s' -ScopeId '%s' -ErrorAction Stop;$a=([ipaddress]'%s').Address;if(($a -lt $scope.StartRange.Address)-or($a -gt $scope.EndRange.Address)){throw 'IP is outside Scope'};if(Get-DhcpServerv4Reservation -ComputerName '%s' -ScopeId '%s' -ErrorAction SilentlyContinue|Where-Object{$_.IPAddress -eq '%s' -or (($_.ClientId-replace'[^0-9A-Fa-f]','').ToUpper() -eq ('%s'-replace'[^0-9A-Fa-f]','').ToUpper())}){throw 'Reservation conflict'};$lease=Get-DhcpServerv4Lease -ComputerName '%s' -ScopeId '%s' -IPAddress '%s' -ErrorAction SilentlyContinue;if($lease -and (($lease.ClientId-replace'[^0-9A-Fa-f]','').ToUpper() -ne ('%s'-replace'[^0-9A-Fa-f]','').ToUpper())){throw 'Active Lease conflict'};Add-DhcpServerv4Reservation -ComputerName '%s' -ScopeId '%s' -IPAddress '%s' -ClientId '%s' -Name '%s' -Description '%s' -ErrorAction Stop`, s, psEscape(r.Scope), psEscape(r.IP), s, psEscape(r.Scope), psEscape(r.IP), psEscape(mac), s, psEscape(r.Scope), psEscape(r.IP), psEscape(mac), s, psEscape(r.Scope), psEscape(r.IP), psEscape(mac), psEscape(r.Name), psEscape(r.VLAN))
	_, e := runPowerShell(script)
	return e
}
func apiReservation(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !canEdit(u) {
		jsonErr(w, "Read-only account", 403)
		return
	}
	var q struct{ MAC, IP, Scope, VLAN, Name string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	m, ok := normalizeMAC(q.MAC)
	if !ok {
		jsonErr(w, "Invalid MAC", 400)
		return
	}
	mu.RLock()
	d := state.Devices[m]
	mu.RUnlock()
	if d == nil {
		jsonErr(w, "MAC not found", 404)
		return
	}
	if d.Disabled {
		if err := addAllow(m, d.Note); err != nil {
			jsonErr(w, err.Error(), 500)
			return
		}
		mu.Lock()
		d.Disabled = false
		_ = saveStateLocked()
		mu.Unlock()
	}
	rv := Reservation{IP: q.IP, Scope: q.Scope, VLAN: q.VLAN, Name: q.Name}
	if err := createReservation(m, rv); err != nil {
		addAudit(u.Username, "reservation_failed", m, err.Error(), clientIP(r))
		jsonErr(w, err.Error(), 409)
		return
	}
	mu.Lock()
	d.Reservation = &rv
	_ = saveStateLocked()
	mu.Unlock()
	addAudit(u.Username, "reservation_create", m, fmt.Sprintf("IP=%s Scope=%s VLAN=%s", q.IP, q.Scope, q.VLAN), clientIP(r))
	jsonOut(w, map[string]bool{"ok": true})
}

func fetchDHCPTopology() (DHCPTopology, error) {
	s := psEscape(cfg.DHCPServer)
	script := fmt.Sprintf(`$scopes=@(Get-DhcpServerv4Scope -ComputerName '%s' -ErrorAction Stop|ForEach-Object{[pscustomobject]@{scope=$_.ScopeId.IPAddressToString;name=$_.Name;start=$_.StartRange.IPAddressToString;end=$_.EndRange.IPAddressToString;mask=$_.SubnetMask.IPAddressToString;state=[string]$_.State;vlan=$_.Name}});$reservations=@(Get-DhcpServerv4Scope -ComputerName '%s' -ErrorAction Stop|ForEach-Object{$sid=$_.ScopeId.IPAddressToString;Get-DhcpServerv4Reservation -ComputerName '%s' -ScopeId $_.ScopeId -ErrorAction SilentlyContinue|ForEach-Object{[pscustomobject]@{scope=$sid;ip=$_.IPAddress.IPAddressToString;mac=$_.ClientId;name=$_.Name;description=$_.Description}}});[pscustomobject]@{scopes=$scopes;reservations=$reservations}|ConvertTo-Json -Depth 5 -Compress`, s, s, s)
	b, e := runPowerShell(script)
	if e != nil {
		return DHCPTopology{}, e
	}
	var t DHCPTopology
	e = json.Unmarshal(b, &t)
	if t.Scopes == nil {
		t.Scopes = []ScopeInfo{}
	}
	if t.Reservations == nil {
		t.Reservations = []ReservationInfo{}
	}
	for i := range t.Reservations {
		if m, ok := normalizeMAC(t.Reservations[i].MAC); ok {
			t.Reservations[i].MAC = m
		}
	}
	return t, e
}
func apiReservations(w http.ResponseWriter, r *http.Request) {
	_, ok := requireAuth(w, r)
	if !ok {
		return
	}
	t, e := fetchDHCPTopology()
	if e != nil {
		startupLog("reservation module read failed: %v", e)
		jsonErr(w, e.Error(), 500)
		return
	}
	jsonOut(w, t)
}
func apiReservationDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !canEdit(u) {
		jsonErr(w, "Read-only account", 403)
		return
	}
	var q struct{ Scope, IP, MAC string }
	if parseJSON(r, &q) != nil || net.ParseIP(q.Scope) == nil || net.ParseIP(q.IP) == nil {
		jsonErr(w, "Invalid request", 400)
		return
	}
	s := psEscape(cfg.DHCPServer)
	script := fmt.Sprintf("Remove-DhcpServerv4Reservation -ComputerName '%s' -ScopeId '%s' -IPAddress '%s' -Confirm:$false -ErrorAction Stop", s, psEscape(q.Scope), psEscape(q.IP))
	if _, e := runPowerShell(script); e != nil {
		addAudit(u.Username, "reservation_delete_failed", q.MAC, e.Error(), clientIP(r))
		jsonErr(w, e.Error(), 500)
		return
	}
	if m, valid := normalizeMAC(q.MAC); valid {
		mu.Lock()
		if d := state.Devices[m]; d != nil && d.Reservation != nil && d.Reservation.IP == q.IP {
			d.Reservation = nil
			_ = saveStateLocked()
		}
		mu.Unlock()
		addAudit(u.Username, "reservation_delete", m, "IP="+q.IP+" Scope="+q.Scope, clientIP(r))
	}
	jsonOut(w, map[string]bool{"ok": true})
}

func reservationsPage(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	_ = reservationsPageTpl2.Execute(w, map[string]interface{}{"Username": template.HTMLEscapeString(u.Username), "CanEdit": canEdit(u)})
}
func recyclePage(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	_ = recyclePageTpl2.Execute(w, map[string]interface{}{"Username": template.HTMLEscapeString(u.Username)})
}
func apiDeviceToggle(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !canEdit(u) {
		jsonErr(w, "Read-only account", 403)
		return
	}
	var q struct {
		MAC     string
		Enabled bool
	}
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	mac, ok := normalizeMAC(q.MAC)
	if !ok {
		jsonErr(w, "Invalid MAC", 400)
		return
	}
	mu.RLock()
	d0 := state.Devices[mac]
	mu.RUnlock()
	if d0 == nil {
		jsonErr(w, "MAC not found", 404)
		return
	}
	if q.Enabled == !d0.Disabled {
		jsonOut(w, map[string]bool{"ok": true})
		return
	}
	var err error
	if q.Enabled {
		err = addAllow(mac, d0.Note)
	} else {
		err = addDeny(mac, d0.Note)
	}
	if err != nil {
		action := "disable_mac_failed"
		if q.Enabled {
			action = "enable_mac_failed"
		}
		addAudit(u.Username, action, mac, "DHCP move failed: "+err.Error(), clientIP(r))
		jsonErr(w, err.Error(), 500)
		return
	}
	now := nowISO()
	mu.Lock()
	d := state.Devices[mac]
	d.Disabled = !q.Enabled
	d.IsOnline = false
	d.OnlineSince = ""
	d.MissedChecks = 0
	if !q.Enabled {
		d.LastOfflineAt = now
	}
	d.UpdatedAt = now
	d.UpdatedBy = u.Username
	_ = saveStateLocked()
	mu.Unlock()
	if q.Enabled {
		updateSyncFields(map[string]interface{}{"last_allow_sync": now, "last_deny_sync": now, "allow_mode": "realtime"})
		addAudit(u.Username, "enable_mac", mac, "Moved MAC from DHCP Deny to Allow", clientIP(r))
	} else {
		updateSyncFields(map[string]interface{}{"last_allow_sync": now, "last_deny_sync": now, "allow_mode": "realtime"})
		addAudit(u.Username, "disable_mac", mac, "Moved MAC from DHCP Allow to Deny", clientIP(r))
	}
	jsonOut(w, map[string]bool{"ok": true})
}

func apiDisableNever(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		jsonErr(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.RLock()
	items := make([]filterMoveItem, 0)
	for _, d := range state.Devices {
		if st, _ := statusOf(d); st == "never" {
			items = append(items, filterMoveItem{MAC: d.MAC, Note: d.Note})
		}
	}
	mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].MAC < items[j].MAC })
	if len(items) == 0 {
		jsonOut(w, map[string]interface{}{"ok": true, "matched": 0, "disabled": 0, "failed": []filterMoveResult{}})
		return
	}

	results, err := moveFiltersToDeny(items)
	if err != nil {
		addAudit(u.Username, "bulk_disable_never_failed", "", "Batch DHCP operation failed: "+err.Error(), clientIP(r))
		jsonErr(w, err.Error(), 500)
		return
	}
	now := nowISO()
	failed := make([]filterMoveResult, 0)
	disabled := 0
	mu.Lock()
	for _, result := range results {
		if !result.OK {
			failed = append(failed, result)
			state.Audit = append(state.Audit, Audit{Time: now, Username: u.Username, Action: "bulk_disable_never_failed", MAC: result.MAC, Detail: "DHCP move to Deny failed: " + result.Error, ClientIP: clientIP(r)})
			continue
		}
		d := state.Devices[result.MAC]
		if d == nil {
			continue
		}
		if st, _ := statusOf(d); st != "never" {
			continue
		}
		d.Disabled = true
		d.IsOnline = false
		d.OnlineSince = ""
		d.MissedChecks = 0
		d.LastOfflineAt = now
		d.UpdatedAt = now
		d.UpdatedBy = u.Username
		disabled++
		state.Audit = append(state.Audit, Audit{Time: now, Username: u.Username, Action: "bulk_disable_never", MAC: result.MAC, Detail: "Never-connected MAC moved from DHCP Allow to Deny", ClientIP: clientIP(r)})
	}
	if len(state.Audit) > 10000 {
		state.Audit = state.Audit[len(state.Audit)-10000:]
	}
	_ = saveStateLocked()
	mu.Unlock()
	if disabled > 0 {
		updateSyncFields(map[string]interface{}{"last_allow_sync": now, "last_deny_sync": now, "allow_mode": "realtime"})
	}
	jsonOut(w, map[string]interface{}{"ok": len(failed) == 0, "matched": len(items), "disabled": disabled, "failed": failed})
}
func apiSync(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	if !canEdit(u) {
		jsonErr(w, "Operator or admin permission required", 403)
		return
	}
	res := syncDHCP()
	addAudit(u.Username, "sync", "", fmt.Sprint(res["message"]), clientIP(r))
	if o, ok := res["ok"].(bool); ok && !o {
		w.WriteHeader(500)
	}
	jsonOut(w, res)
}

func apiExport(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAuth(w, r)
	if !ok {
		return
	}
	addAudit(u.Username, "export_csv", "", "Exported MAC list", clientIP(r))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="dhcp_mac_export.csv"`)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"MAC", "Name", "Note", "Enabled", "Status", "IsOnline", "OnlineSince", "LastDetected", "LastOfflineAt", "LastIP", "Hostname", "Scope", "LastLeaseExpiry", "ActiveLeaseCount", "CreatedBy", "CreatedAt", "UpdatedBy", "UpdatedAt"})
	mu.RLock()
	keys := make([]string, 0, len(state.Devices))
	for k := range state.Devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d := state.Devices[k]
		st, _ := statusOf(d)
		_ = cw.Write([]string{d.MAC, d.Name, d.Note, fmt.Sprint(!d.Disabled), st, fmt.Sprint(d.IsOnline), d.OnlineSince, d.LastSeen, d.LastOfflineAt, d.LastIP, d.Hostname, d.Scope, d.LastLeaseExpiry, fmt.Sprint(d.ActiveLeaseCount), d.CreatedBy, d.CreatedAt, d.UpdatedBy, d.UpdatedAt})
	}
	mu.RUnlock()
	cw.Flush()
}

func apiImport(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		jsonErr(w, "Invalid upload", 400)
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, "CSV file required", 400)
		return
	}
	defer f.Close()
	cr := csv.NewReader(f)
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		jsonErr(w, "CSV parse failed: "+err.Error(), 400)
		return
	}
	if len(rows) < 1 {
		jsonErr(w, "Empty CSV", 400)
		return
	}
	start := 0
	idxMAC, idxName, idxNote, idxEnabled := 0, 1, 2, -1
	header := rows[0]
	foundHeader := false
	for i, h := range header {
		v := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		switch v {
		case "mac", "mac address", "mac地址":
			idxMAC = i
			foundHeader = true
		case "name", "username", "user / device", "用户名", "用户名/设备名":
			idxName = i
		case "note", "remark", "description", "备注", "备注 / allow description":
			idxNote = i
		case "enabled", "enable", "active", "启用", "状态":
			idxEnabled = i
		}
	}
	if foundHeader {
		start = 1
	}
	type item struct {
		mac, name, note string
		enabled         bool
	}
	items := []item{}
	bad := 0
	for _, row := range rows[start:] {
		if idxMAC >= len(row) {
			bad++
			continue
		}
		mac, ok := normalizeMAC(row[idxMAC])
		if !ok {
			bad++
			continue
		}
		name, note := "", ""
		if idxName < len(row) {
			name = row[idxName]
		}
		if idxNote < len(row) {
			note = row[idxNote]
		}
		enabled := true
		if idxEnabled >= 0 && idxEnabled < len(row) {
			v := strings.ToLower(strings.TrimSpace(row[idxEnabled]))
			if v == "false" || v == "0" || v == "no" || v == "disabled" || v == "停用" || v == "已停用" {
				enabled = false
			}
		}
		items = append(items, item{mac, strings.TrimSpace(name), strings.TrimSpace(note), enabled})
	}
	if len(items) == 0 {
		jsonErr(w, "No valid MAC rows", 400)
		return
	}
	// Batch PowerShell for speed.
	var ps strings.Builder
	ps.WriteString("$errs=@();")
	for _, it := range items {
		target := "Allow"
		if !it.enabled {
			target = "Deny"
		}
		ps.WriteString(fmt.Sprintf("try { Remove-DhcpServerv4Filter -ComputerName '%s' -MacAddress '%s' -Confirm:$false -ErrorAction SilentlyContinue; Add-DhcpServerv4Filter -ComputerName '%s' -List %s -MacAddress '%s' -Description '%s' -Force } catch { $errs += '%s:'+$_.Exception.Message };", psEscape(cfg.DHCPServer), psEscape(it.mac), psEscape(cfg.DHCPServer), target, psEscape(it.mac), psEscape(it.note), psEscape(it.mac)))
	}
	ps.WriteString("$errs | ConvertTo-Json -Compress")
	if b, e := runPowerShell(ps.String()); e != nil {
		jsonErr(w, e.Error()+" "+string(b), 500)
		return
	}
	type auditItem struct{ action, mac, detail string }
	auditItems := []auditItem{}
	mu.Lock()
	for _, it := range items {
		d := state.Devices[it.mac]
		if d == nil {
			d = &Device{MAC: it.mac, CreatedAt: nowISO(), CreatedBy: u.Username}
			state.Devices[it.mac] = d
			auditItems = append(auditItems, auditItem{"add_mac_import", it.mac, fmt.Sprintf("Added by CSV import; enabled=%v; note=%s", it.enabled, it.note)})
		} else {
			auditItems = append(auditItems, auditItem{"update_mac_import", it.mac, fmt.Sprintf("Updated by CSV import; enabled=%v; note: %q -> %q", it.enabled, d.Note, it.note)})
		}
		d.Name = it.name
		d.Note = it.note
		d.Disabled = !it.enabled
		d.UpdatedAt = nowISO()
		d.UpdatedBy = u.Username
	}
	_ = saveStateLocked()
	mu.Unlock()
	for _, a := range auditItems {
		addAudit(u.Username, a.action, a.mac, a.detail, clientIP(r))
	}
	addAudit(u.Username, "import_csv", "", fmt.Sprintf("Imported %d MAC rows to DHCP Allow/Deny; skipped %d invalid rows", len(items), bad), clientIP(r))
	jsonOut(w, map[string]interface{}{"ok": true, "imported": len(items), "skipped": bad})
}

func apiLogs(w http.ResponseWriter, r *http.Request) {
	_, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	mu.RLock()
	a := append([]Audit{}, state.Audit...)
	mu.RUnlock()
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
	jsonOut(w, map[string]interface{}{"logs": a})
}
func logsPage(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	_ = logsTpl.Execute(w, map[string]string{"Username": u.Username})
}
func usersPage(w http.ResponseWriter, r *http.Request) {
	u, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	_ = usersTpl.Execute(w, map[string]string{"Username": u.Username})
}
func apiUsers(w http.ResponseWriter, r *http.Request) {
	_, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	mu.RLock()
	arr := []map[string]interface{}{}
	for _, u := range state.Users {
		arr = append(arr, map[string]interface{}{"username": u.Username, "role": u.Role, "enabled": u.Enabled, "created_at": u.CreatedAt, "created_by": u.CreatedBy})
	}
	mu.RUnlock()
	sort.Slice(arr, func(i, j int) bool { return arr[i]["username"].(string) < arr[j]["username"].(string) })
	jsonOut(w, map[string]interface{}{"users": arr})
}
func apiUserAdd(w http.ResponseWriter, r *http.Request) {
	admin, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct{ Username, Password, Role string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	q.Username = strings.TrimSpace(q.Username)
	if len(q.Username) < 3 || len(q.Password) < 8 {
		jsonErr(w, "Username >=3 and password >=8", 400)
		return
	}
	q.Role = strings.ToLower(strings.TrimSpace(q.Role))
	if q.Role != "admin" && q.Role != "operator" && q.Role != "viewer" {
		q.Role = "operator"
	}
	mu.Lock()
	if _, exists := state.Users[q.Username]; exists {
		mu.Unlock()
		jsonErr(w, "User already exists", 409)
		return
	}
	salt, hash := newPassword(q.Password)
	state.Users[q.Username] = &User{Username: q.Username, Role: q.Role, Salt: salt, PasswordHash: hash, CreatedAt: nowISO(), CreatedBy: admin.Username, Enabled: true}
	_ = saveStateLocked()
	mu.Unlock()
	addAudit(admin.Username, "add_user", "", "Created user "+q.Username+" role="+q.Role, clientIP(r))
	jsonOut(w, map[string]bool{"ok": true})
}
func apiUserPassword(w http.ResponseWriter, r *http.Request) {
	admin, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct{ Username, Password string }
	if parseJSON(r, &q) != nil || len(q.Password) < 8 {
		jsonErr(w, "Password >=8", 400)
		return
	}
	mu.Lock()
	u := state.Users[q.Username]
	if u == nil {
		mu.Unlock()
		jsonErr(w, "User not found", 404)
		return
	}
	u.Salt, u.PasswordHash = newPassword(q.Password)
	_ = saveStateLocked()
	mu.Unlock()
	sessionMu.Lock()
	for token, sess := range sessions {
		if sess.Username == q.Username {
			delete(sessions, token)
		}
	}
	sessionMu.Unlock()
	addAudit(admin.Username, "reset_password", "", "Reset password and invalidated active sessions for "+q.Username, clientIP(r))
	jsonOut(w, map[string]bool{"ok": true})
}
func apiUserToggle(w http.ResponseWriter, r *http.Request) {
	admin, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct {
		Username string
		Enabled  bool
	}
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid", 400)
		return
	}
	if q.Username == admin.Username && !q.Enabled {
		jsonErr(w, "Cannot disable current admin", 400)
		return
	}
	mu.Lock()
	u := state.Users[q.Username]
	if u == nil {
		mu.Unlock()
		jsonErr(w, "Not found", 404)
		return
	}
	old := u.Enabled
	u.Enabled = q.Enabled
	_ = saveStateLocked()
	mu.Unlock()
	kicked := 0
	if !q.Enabled {
		sessionMu.Lock()
		for token, sess := range sessions {
			if sess.Username == q.Username {
				delete(sessions, token)
				kicked++
			}
		}
		sessionMu.Unlock()
	}
	addAudit(admin.Username, "toggle_user", "", fmt.Sprintf("User %s enabled: %v -> %v; invalidated_sessions=%d", q.Username, old, q.Enabled, kicked), clientIP(r))
	jsonOut(w, map[string]interface{}{"ok": true, "invalidated_sessions": kicked})
}

func apiUserRole(w http.ResponseWriter, r *http.Request) {
	admin, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct{ Username, Role string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	q.Role = strings.ToLower(strings.TrimSpace(q.Role))
	if q.Role != "admin" && q.Role != "operator" && q.Role != "viewer" {
		jsonErr(w, "Invalid role", 400)
		return
	}
	mu.Lock()
	u := state.Users[q.Username]
	if u == nil {
		mu.Unlock()
		jsonErr(w, "User not found", 404)
		return
	}
	if q.Username == admin.Username && q.Role != "admin" {
		mu.Unlock()
		jsonErr(w, "Cannot remove your own admin role", 400)
		return
	}
	old := u.Role
	u.Role = q.Role
	_ = saveStateLocked()
	mu.Unlock()
	addAudit(admin.Username, "change_user_role", "", fmt.Sprintf("Changed user %s role: %s -> %s", q.Username, old, q.Role), clientIP(r))
	jsonOut(w, map[string]bool{"ok": true})
}

func apiUserDelete(w http.ResponseWriter, r *http.Request) {
	admin, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	var q struct{ Username string }
	if parseJSON(r, &q) != nil {
		jsonErr(w, "Invalid JSON", 400)
		return
	}
	if q.Username == admin.Username {
		jsonErr(w, "Cannot delete current admin", 400)
		return
	}
	mu.Lock()
	u := state.Users[q.Username]
	if u == nil {
		mu.Unlock()
		jsonErr(w, "User not found", 404)
		return
	}
	if u.Role == "admin" && u.Enabled {
		n := 0
		for _, x := range state.Users {
			if x.Role == "admin" && x.Enabled {
				n++
			}
		}
		if n <= 1 {
			mu.Unlock()
			jsonErr(w, "Cannot delete the last enabled admin", 400)
			return
		}
	}
	delete(state.Users, q.Username)
	_ = saveStateLocked()
	mu.Unlock()
	// Invalidate any sessions belonging to this user.
	sessionMu.Lock()
	for token, sess := range sessions {
		if sess.Username == q.Username {
			delete(sessions, token)
		}
	}
	sessionMu.Unlock()
	addAudit(admin.Username, "delete_user", "", "Deleted user "+q.Username, clientIP(r))
	jsonOut(w, map[string]bool{"ok": true})
}

func main() {
	baseDir = exeDir()
	dataPath = filepath.Join(baseDir, "dhcp_monitor_data.json")
	lf, err := os.OpenFile(filepath.Join(baseDir, "startup.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		defer lf.Close()
		startupLogger = log.New(lf, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	defer func() {
		if v := recover(); v != nil {
			startupLog("PANIC: %v", v)
			if startupLogger != nil {
				startupLogger.Printf("program stopped after recovered panic")
			}
		}
	}()
	startupLog("DHCP MAC Monitor v1.7.1 starting; base=%s", baseDir)
	if err := loadConfig(); err != nil {
		startupLog("%v; safe defaults retained", err)
	}
	backupDataOnStartup()
	if err := loadState(); err != nil {
		startupLog("state initialization failed: %v; continuing", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("DHCP MAC Monitor v1.7.1 OK"))
	})
	mux.HandleFunc("/login", loginPage)
	mux.HandleFunc("/setup", setupPage)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/", dashboard)
	mux.HandleFunc("/logs", logsPage)
	mux.HandleFunc("/users", usersPage)
	mux.HandleFunc("/reservations", reservationsPage)
	mux.HandleFunc("/recycle", recyclePage)
	mux.HandleFunc("/api/devices", apiDevices)
	mux.HandleFunc("/api/add", apiAdd)
	mux.HandleFunc("/api/update", apiUpdate)
	mux.HandleFunc("/api/delete", apiDelete)
	mux.HandleFunc("/api/device/toggle", apiDeviceToggle)
	mux.HandleFunc("/api/devices/disable-never", apiDisableNever)
	mux.HandleFunc("/api/devices/delete-disabled", apiBulkDeleteDisabled)
	mux.HandleFunc("/api/recycle", apiRecycle)
	mux.HandleFunc("/api/recycle/restore", apiRecycleRestore)
	mux.HandleFunc("/api/reservation", apiReservation)
	mux.HandleFunc("/api/reservations", apiReservations)
	mux.HandleFunc("/api/reservation/delete", apiReservationDelete)
	mux.HandleFunc("/api/sync", apiSync)
	mux.HandleFunc("/api/export", apiExport)
	mux.HandleFunc("/api/import", apiImport)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/users", apiUsers)
	mux.HandleFunc("/api/users/add", apiUserAdd)
	mux.HandleFunc("/api/users/password", apiUserPassword)
	mux.HandleFunc("/api/users/toggle", apiUserToggle)
	mux.HandleFunc("/api/users/role", apiUserRole)
	mux.HandleFunc("/api/users/delete", apiUserDelete)

	go func() {
		defer func() {
			if v := recover(); v != nil {
				startupLog("BACKGROUND PANIC RECOVERED: %v; web UI remains available", v)
			}
		}()
		// Start HTTP immediately and perform the required startup DHCP check in the
		// background. A short delay prevents PowerShell startup from competing with
		// the first browser connection while still checking immediately after launch.
		updateSyncFields(map[string]interface{}{"message": "Startup DHCP check running", "startup_sync": true})
		time.Sleep(350 * time.Millisecond)
		func() {
			defer func() {
				if v := recover(); v != nil {
					startupLog("startup modules panic: %v; web UI remains available", v)
				}
			}()
			res := syncDHCP()
			if ok, _ := res["ok"].(bool); !ok {
				startupLog("startup DHCP modules failed: %v; web UI remains available", res["message"])
			}
		}()
		updateSyncFields(map[string]interface{}{"startup_sync": false})
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			func() {
				defer func() {
					if v := recover(); v != nil {
						startupLog("SCHEDULED SYNC PANIC RECOVERED: %v; next cycle will continue", v)
					}
				}()
				now := time.Now()
				leaseDue, denyDue := getDueTimes()
				if leaseDue.IsZero() || !now.Before(leaseDue) {
					syncLeasesOnly()
				}
				if denyDue.IsZero() || !now.Before(denyDue) {
					syncDenyOnly()
				}
			}()
		}
	}()

	addr := fmt.Sprintf("%s:%d", cfg.Listen, cfg.Port)
	fmt.Printf("DHCP MAC Monitor v1.7.1\nLocal: http://127.0.0.1:%d\nListening: %s\n", cfg.Port, addr)
	listener, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		startupLog("port listen failed addr=%s: %v", addr, listenErr)
		fmt.Fprintf(os.Stderr, "Cannot listen on %s: %v; see startup.log\n", addr, listenErr)
		return
	}
	startupLog("listening confirmed on %s", listener.Addr())
	go func() {
		time.Sleep(750 * time.Millisecond)
		client := http.Client{Timeout: 5 * time.Second}
		url := fmt.Sprintf("http://127.0.0.1:%d/_health", cfg.Port)
		resp, e := client.Get(url)
		if e != nil {
			startupLog("SELF-TEST FAILED %s: %v", url, e)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		startupLog("SELF-TEST OK status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}()
	if err := http.Serve(listener, requestLog(noCache(mux))); err != nil {
		startupLog("port listen failed addr=%s: %v", addr, err)
		fmt.Fprintf(os.Stderr, "Cannot listen on %s: %v; see startup.log\n", addr, err)
	}
}

var loginTpl = template.Must(template.New("login").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>DHCP MAC Monitor - Login</title><style>` + baseCSS + `</style></head><body><div class="auth"><div class="card"><h1>DHCP MAC Monitor</h1><p class="muted">Account authentication / 账号认证 / Xác thực tài khoản</p>{{if .Msg}}<div class="error">{{.Msg}}</div>{{end}}<form method="post"><label>Username / 用户名</label><input name="username" autocomplete="username" required><label>Password / 密码</label><input type="password" name="password" autocomplete="current-password" required><button class="btn primary full">Login / 登录</button></form></div></div></body></html>`))
var setupTpl = template.Must(template.New("setup").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>First Setup</title><style>` + baseCSS + `</style></head><body><div class="auth"><div class="card"><h1>First-time setup</h1><p class="muted">Create the first administrator account. / 创建第一个管理员账号。</p>{{if .Msg}}<div class="error">{{.Msg}}</div>{{end}}<form method="post"><label>Admin username</label><input name="username" required minlength="3"><label>Admin password (8+)</label><input type="password" name="password" required minlength="8"><button class="btn primary full">Create administrator</button></form></div></div></body></html>`))

const baseCSS = `*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Microsoft YaHei,Arial,sans-serif;background:#f3f6fb;color:#14213a}.wrap{max-width:1680px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap}.brand h1,h1{margin:0;font-size:28px;letter-spacing:-.4px}.brand .muted{margin-top:5px}.muted{color:#74839b}.nav{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.btn{border:1px solid #dbe4f0;border-radius:10px;background:#fff;padding:9px 13px;font-weight:700;color:#16233b;cursor:pointer;transition:.16s ease;white-space:nowrap}.btn:hover{border-color:#9fb1c9;box-shadow:0 4px 14px rgba(29,56,98,.08);transform:translateY(-1px)}.btn:disabled{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}.btn.primary{background:#2563eb;color:#fff;border-color:#2563eb}.btn.danger{color:#dc2626;background:#fff5f5;border-color:#fecaca}.btn.soft{background:#f7f9fc}.btn.full{width:100%;margin-top:14px}.cards{display:grid;grid-template-columns:repeat(7,minmax(145px,1fr));gap:12px;margin:20px 0}.stat{position:relative;overflow:hidden;background:#fff;border:1px solid #e1e8f2;border-radius:16px;padding:17px 18px;min-height:110px;box-shadow:0 5px 20px rgba(24,45,79,.035)}.stat:before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:#94a3b8}.stat .statLabel{font-weight:700;color:#52617a}.stat b{display:block;font-size:29px;line-height:1;margin-top:13px}.stat small{display:block;margin-top:8px;color:#8a97aa;font-size:12px}.stat.total:before{background:#334155}.stat.ok:before{background:#22c55e}.stat.ok b{color:#16a34a}.stat.warn:before{background:#f59e0b}.stat.warn b{color:#d97706}.stat.dangerStat:before{background:#ef4444}.stat.dangerStat b{color:#dc2626}.stat.offlineStat:before{background:#8b5cf6}.stat.offlineStat b{color:#7c3aed}.stat.neverStat:before{background:#94a3b8}.stat.disabledStat:before{background:#f43f5e}.stat.disabledStat b{color:#e11d48}.panel{background:#fff;border:1px solid #dfe7f2;border-radius:16px;overflow:hidden;box-shadow:0 8px 28px rgba(24,45,79,.045)}.tools{padding:14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;border-bottom:1px solid #edf1f6}.tools input,.tools select,.nav select{border:1px solid #d9e2ef;border-radius:10px;padding:10px 12px;background:#fff;color:#16233b}.tools input{flex:1;min-width:260px}.tabs{display:flex;gap:6px;flex-wrap:wrap}.activeTab{background:#17233b!important;color:#fff!important;border-color:#17233b!important}.syncBar{padding:9px 16px;background:#f8faff;border-bottom:1px solid #edf1f6;text-align:right;font-size:13px}.tableWrap{overflow:auto;max-height:calc(100vh - 430px);min-height:370px}.deviceTable{min-width:1570px}table{width:100%;border-collapse:separate;border-spacing:0}th,td{padding:11px 12px;border-bottom:1px solid #edf1f6;text-align:left;font-size:13px;vertical-align:middle}th{position:sticky;top:0;background:#f7f9fc;color:#33425b;z-index:5;font-weight:750}tbody tr{transition:.12s ease}tbody tr:hover{background:#f8fbff}tbody tr:hover td:first-child,tbody tr:hover td:last-child{background:#f8fbff}td:first-child,th:first-child{position:sticky;left:0;z-index:4}td:first-child{background:#fff}th:first-child{z-index:7;background:#f7f9fc}td:last-child,th:last-child{position:sticky;right:0;z-index:4;background:#fff;min-width:198px;box-shadow:-8px 0 12px -12px rgba(26,43,71,.35)}th:last-child{z-index:7;background:#f7f9fc}.statusBadge{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:7px 10px;font-weight:750;white-space:nowrap;border:1px solid transparent}.statusBadge .dot{font-size:13px;line-height:1}.status-normal{background:#ecfdf3;color:#16803d;border-color:#bbf7d0}.status-over3{background:#fff7e8;color:#b65f00;border-color:#fed7aa}.status-over7{background:#fff0f1;color:#c81e3a;border-color:#fecdd3}.status-offline{background:#f5f0ff;color:#6d3ec2;border-color:#ddd0ff}.status-never{background:#f2f5f8;color:#66758a;border-color:#e2e8f0}.status-disabled{background:#fff0f3;color:#be123c;border-color:#fecdd3}.duration{font-weight:700}.duration.normal{color:#16803d}.duration.over3{color:#b65f00}.duration.over7{color:#c81e3a}.duration.offline{color:#6d3ec2}.subline{margin-top:4px;color:#8794a8;font-size:12px}.rowActions{display:flex;gap:6px;flex-wrap:nowrap;align-items:center}.rowActions .btn{padding:8px 10px}.pagebar{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:10px 14px;background:#fbfcfe}.pagebar select{border:1px solid #dbe4f0;border-radius:9px;padding:8px}.modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.46);align-items:center;justify-content:center;z-index:50;padding:20px;backdrop-filter:blur(2px)}.modal.show{display:flex}.box{background:#fff;border-radius:17px;padding:22px;width:min(520px,96vw);box-shadow:0 26px 70px rgba(15,23,42,.24)}.box.wide{width:min(760px,96vw)}.box h2{margin:0 0 16px}.box label{display:block;margin:12px 0 6px;font-weight:700}.box input,.box textarea,.box select{width:100%;border:1px solid #d8e1ed;border-radius:10px;padding:10px 12px}.actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}.legendGrid{display:grid;gap:9px}.legendRow{display:grid;grid-template-columns:minmax(180px,240px) 1fr;gap:18px;align-items:center;padding:11px 12px;border:1px solid #e7ecf3;border-radius:12px;background:#fbfcfe}.legendNote{margin-top:14px;padding:11px 12px;border-radius:11px;background:#fff8e8;color:#8a5200;font-size:13px}.auth{min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(420px,94vw);background:#fff;padding:28px;border-radius:17px;border:1px solid #e1e8f2;box-shadow:0 20px 60px rgba(22,36,60,.12)}.card label{display:block;margin:13px 0 6px;font-weight:700}.card input{width:100%;padding:11px;border:1px solid #dbe4f0;border-radius:10px}.error{background:#fff1f2;color:#be123c;padding:10px;border-radius:9px;margin:12px 0}@media(max-width:1450px){.cards{grid-template-columns:repeat(4,1fr)}}@media(max-width:900px){.wrap{padding:14px}.cards{grid-template-columns:repeat(2,1fr)}.tableWrap{max-height:calc(100vh - 470px)}.legendRow{grid-template-columns:1fr}.top{align-items:flex-start}}`

const layoutFixCSS = `.wrap{max-width:2200px;padding:22px 28px}.top{align-items:flex-start}.brand{min-width:330px}.nav{justify-content:flex-end}.reservationForm{display:grid;grid-template-columns:minmax(230px,1fr) minmax(340px,1.5fr) minmax(210px,1fr) minmax(190px,1fr) minmax(190px,1fr) auto;gap:10px;align-items:center}.reservationForm input,.reservationForm select{width:100%;min-width:0;border:1px solid #d9e2ef;border-radius:10px;padding:10px 12px;background:#fff;color:#16233b}.scopePanel .tableWrap{max-height:none;overflow-x:auto;overflow-y:visible}.scopePanel table{min-width:980px}@media(max-width:1500px){.reservationForm{grid-template-columns:repeat(3,minmax(200px,1fr))}.reservationForm .primary{justify-self:start}}@media(max-width:800px){.wrap{padding:14px}.reservationForm{grid-template-columns:1fr}.nav{justify-content:flex-start}}`

var dashboardTpl = template.Must(template.New("dash").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>DHCP MAC Manager</title><style>` + baseCSS + layoutFixCSS + `</style></head>
<body><div class="wrap">
<div class="top"><div class="brand"><h1 data-i="title">DHCP MAC 设备管理 V1.7.1</h1><div class="muted" data-i="sub">DHCP Allow 实时管理 + Lease 检测 + Deny 同步</div></div><div class="nav"><span class="muted">{{.Username}} ({{.Role}})</span><select id="lang"><option value="zh">中文</option><option value="en">English</option><option value="vi">Tiếng Việt</option></select><a class="btn" href="/reservations">固定 IP / VLAN</a>{{if .IsAdmin}}<a class="btn" href="/logs" data-i="logs">审核日志</a><a class="btn" href="/users" data-i="users">账号管理</a><button class="btn danger" onclick="deleteDisabled()">一键删除已停用</button><a class="btn" href="/recycle">回收站</a>{{end}}<a class="btn" href="/api/export" data-i="export">导出 CSV</a>{{if .IsAdmin}}<button id="importBtn" class="btn" onclick="document.getElementById('file').click()" data-i="import">导入 CSV</button><input id="file" type="file" accept=".csv,text/csv" style="display:none" onchange="importCSV(this)">{{end}}{{if .CanEdit}}<button id="syncBtn" class="btn" onclick="syncNow()" data-i="sync">立即同步</button><button id="addBtn" class="btn primary" onclick="openAdd()" data-i="add">+ 添加 MAC</button>{{end}}<a class="btn" href="/logout" data-i="logout">退出</a></div></div>
<div class="cards"><div class="stat total"><span class="statLabel" data-i="total">管理 MAC 总数</span><b id="nTotal">0</b><small data-i="totalHint">Allow 与 Deny 管理记录</small></div><div class="stat ok"><span class="statLabel" data-i="ok">在线3天以内</span><b id="nOk">0</b><small data-i="okHint">连续在线 ≤ 3天</small></div><div class="stat warn"><span class="statLabel" data-i="d3">在线超过3天</span><b id="n3">0</b><small data-i="d3Hint">连续在线 >3天 且 ≤7天</small></div><div class="stat dangerStat"><span class="statLabel" data-i="d7">在线超过7天</span><b id="n7">0</b><small data-i="d7Hint">连续在线 > 7天</small></div><div class="stat offlineStat"><span class="statLabel" data-i="offline">当前离线</span><b id="nOffline">0</b><small data-i="offlineHint">连续两次检查未发现</small></div><div class="stat neverStat"><span class="statLabel" data-i="never">从未连接</span><b id="nNever">0</b><small data-i="neverHint">添加后从未在 DHCP 发现</small></div><div class="stat disabledStat"><span class="statLabel" data-i="disabled">已停用</span><b id="nDisabled">0</b><small data-i="disabledHint">MAC 已移动到 Deny</small></div></div>
<div class="panel"><div class="tools"><input id="q" data-ph="search" oninput="page=1;render()"><div class="tabs"><button class="btn activeTab" onclick="setFilter('all',this)" data-i="all">全部</button><button class="btn" onclick="setFilter('normal',this)" data-i="onlyNormal">在线≤3天</button><button class="btn" onclick="setFilter('over3',this)" data-i="only3">在线>3天</button><button class="btn" onclick="setFilter('over7',this)" data-i="only7">在线>7天</button><button class="btn" onclick="setFilter('offline',this)" data-i="onlyOffline">当前离线</button><button class="btn" onclick="setFilter('never',this)" data-i="onlyNever">从未连接</button><button class="btn" onclick="setFilter('disabled',this)" data-i="onlyDisabled">已停用</button></div>{{if .IsAdmin}}<button id="disableNeverBtn" class="btn danger" style="display:none" onclick="disableNever()" data-i="disableNever">一键停用从未连接</button>{{end}}<button class="btn soft" onclick="openLegend()" data-i="legend">状态说明</button></div><div class="syncBar"><span id="syncMsg" class="muted"></span></div>
<div class="tableWrap"><table class="deviceTable"><thead><tr><th data-i="status">状态</th><th>MAC</th><th data-i="name">用户名/设备名</th><th data-i="note">备注 / Allow Description</th><th data-i="ip">最后 IP</th><th data-i="scope">网段</th><th data-i="onlineSince">本次上线</th><th data-i="lastDetected">最后检测</th><th data-i="stateDuration">连续状态</th><th data-i="leaseInfo">Lease 信息</th><th data-i="creator">添加账号</th><th data-i="act">操作</th></tr></thead><tbody id="rows"></tbody></table></div><div class="pagebar"><span id="pageInfo" class="muted"></span><button id="prevBtn" class="btn" onclick="changePage(-1)">‹</button><button id="nextBtn" class="btn" onclick="changePage(1)">›</button><select id="pageSize" onchange="setPageSize(this.value)"><option value="50">50 / 页</option><option value="100" selected>100 / 页</option><option value="200">200 / 页</option></select></div></div></div>
<div id="modal" class="modal"><div class="box"><h2 id="mTitle"></h2><label>MAC</label><input id="mMac" placeholder="aa:bb:cc:dd:ee:ff / AABBCCDDEEFF" oninput="formatMAC(this)"><label data-i="name">用户名/设备名</label><input id="mName"><label data-i="noteShort">备注</label><textarea id="mNote" rows="3"></textarea><div class="muted" style="margin-top:8px" data-i="macHint">MAC 会自动统一为 AA-BB-CC-DD-EE-FF，并同步到 Windows DHCP Allow。</div><div class="actions"><button class="btn" onclick="closeModal()" data-i="cancel">取消</button><button class="btn primary" onclick="saveModal()" data-i="save">保存</button></div></div></div>
<div id="legendModal" class="modal"><div class="box wide"><h2 data-i="legendTitle">状态分类</h2><div class="legendGrid"><div class="legendRow"><span class="statusBadge status-normal"><span class="dot">●</span><span data-i="normal">在线3天以内</span></span><span data-i="legendNormal">连续在线 ≤ 3天</span></div><div class="legendRow"><span class="statusBadge status-over3"><span class="dot">●</span><span data-i="over3">在线超过3天</span></span><span data-i="legendOver3">连续在线 >3天，且 ≤7天</span></div><div class="legendRow"><span class="statusBadge status-over7"><span class="dot">●</span><span data-i="over7">在线超过7天</span></span><span data-i="legendOver7">连续在线 >7天</span></div><div class="legendRow"><span class="statusBadge status-offline"><span class="dot">●</span><span data-i="offlineS">当前离线</span></span><span data-i="legendOffline">连续两次 Lease 检查未发现</span></div><div class="legendRow"><span class="statusBadge status-never"><span class="dot">○</span><span data-i="neverS">从未连接</span></span><span data-i="legendNever">添加后从未在 DHCP Lease 中发现</span></div><div class="legendRow"><span class="statusBadge status-disabled"><span class="dot">⊘</span><span data-i="disabledS">已停用</span></span><span data-i="legendDisabled">MAC 已从 Allow 移到 Deny</span></div></div><div class="legendNote" data-i="legendNote">说明：状态依据 Windows DHCP Active Lease 判断，不等同于交换机或无线控制器的物理在线状态。升级到 V1.6.0 后，首次检测会建立连续在线计时基线。</div><div class="actions"><button class="btn primary" onclick="closeLegend()" data-i="close">关闭</button></div></div></div>
<script>
const isAdmin={{if .IsAdmin}}true{{else}}false{{end}},canEdit={{if .CanEdit}}true{{else}}false{{end}};
let devices=[],filter='all',editMac='',page=1,pageSize=100,lang=localStorage.getItem('lang')||'zh';
const L={zh:{title:'DHCP MAC 设备管理',sub:'DHCP Allow 实时管理 + Lease 5分钟检测 + Deny 4小时同步',logs:'审核日志',users:'账号管理',export:'导出 CSV',import:'导入 CSV',sync:'立即同步',add:'+ 添加 MAC',logout:'退出',total:'管理 MAC 总数',totalHint:'Allow 与 Deny 管理记录',ok:'在线3天以内',okHint:'连续在线 ≤ 3天',d3:'在线超过3天',d3Hint:'连续在线 >3天 且 ≤7天',d7:'在线超过7天',d7Hint:'连续在线 > 7天',offline:'当前离线',offlineHint:'连续两次检查未发现',never:'从未连接',neverHint:'添加后从未在 DHCP 发现',disabled:'已停用',disabledHint:'MAC 已移动到 Deny',all:'全部',onlyNormal:'在线≤3天',only3:'在线>3天',only7:'在线>7天',onlyOffline:'当前离线',onlyNever:'从未连接',onlyDisabled:'已停用',legend:'状态说明',legendTitle:'状态分类',legendNormal:'连续在线 ≤ 3天',legendOver3:'连续在线 >3天，且 ≤7天',legendOver7:'连续在线 >7天',legendOffline:'连续两次 Lease 检查未发现',legendNever:'添加后从未在 DHCP Lease 中发现',legendDisabled:'MAC 已从 Allow 移到 Deny',legendNote:'说明：状态依据 Windows DHCP Active Lease 判断，不等同于交换机或无线控制器的物理在线状态。升级到 V1.6.0 后，首次检测会建立连续在线计时基线。',status:'状态',name:'用户名/设备名',note:'备注 / Allow Description',noteShort:'备注',ip:'最后 IP',scope:'网段',onlineSince:'本次上线',lastDetected:'最后检测',stateDuration:'连续状态',leaseInfo:'Lease 信息',creator:'添加账号',act:'操作',search:'搜索 MAC / 用户名 / 备注 / IP / 添加账号',normal:'在线3天以内',over3:'在线超过3天',over7:'在线超过7天',offlineS:'当前离线',neverS:'从未连接',disabledS:'已停用',continuousOnline:'连续在线',offlineFor:'已离线',edit:'修改',del:'删除',disable:'停用',enable:'启用',cancel:'取消',save:'保存',close:'关闭',addT:'添加 MAC',editT:'修改设备',macHint:'MAC 会自动统一为 AA-BB-CC-DD-EE-FF，并同步到 Windows DHCP Allow。',days:'天',hours:'小时',minutes:'分钟',leaseCheck:'Lease最后检查',next:'下次',allowMode:'Allow',realtime:'实时',denySync:'Deny最后同步',duration:'检查耗时',multi:'多 Lease',expiry:'到期',confirm:'确认删除，并同时从 DHCP Allow/Deny 清除吗？'},en:{title:'DHCP MAC Device Management',sub:'Real-time Allow + Lease check every 5 minutes + Deny sync every 4 hours',logs:'Audit logs',users:'Accounts',export:'Export CSV',import:'Import CSV',sync:'Sync now',add:'+ Add MAC',logout:'Logout',total:'Managed MACs',totalHint:'Allow and Deny records',ok:'Online within 3 days',okHint:'Continuous online ≤ 3 days',d3:'Online over 3 days',d3Hint:'Continuous online >3 and ≤7 days',d7:'Online over 7 days',d7Hint:'Continuous online > 7 days',offline:'Currently offline',offlineHint:'Missing in two consecutive checks',never:'Never connected',neverHint:'Never found in DHCP after adding',disabled:'Disabled',disabledHint:'MAC moved to Deny',all:'All',onlyNormal:'Online ≤3d',only3:'Online >3d',only7:'Online >7d',onlyOffline:'Offline',onlyNever:'Never connected',onlyDisabled:'Disabled',legend:'Status guide',legendTitle:'Status classification',legendNormal:'Continuous online ≤ 3 days',legendOver3:'Continuous online >3 days and ≤7 days',legendOver7:'Continuous online >7 days',legendOffline:'Not found in two consecutive Lease checks',legendNever:'Never found in DHCP Lease after being added',legendDisabled:'MAC has been moved from Allow to Deny',legendNote:'Note: status is based on Windows DHCP Active Lease records and is not the same as physical online state from a switch or wireless controller. The first V1.6.0 scan establishes the continuous-online baseline.',status:'Status',name:'User / Device',note:'Note / Allow Description',noteShort:'Note',ip:'Last IP',scope:'Scope',onlineSince:'Online since',lastDetected:'Last detected',stateDuration:'Continuous state',leaseInfo:'Lease info',creator:'Added by',act:'Actions',search:'Search MAC / user / note / IP / account',normal:'Online within 3 days',over3:'Online over 3 days',over7:'Online over 7 days',offlineS:'Currently offline',neverS:'Never connected',disabledS:'Disabled',continuousOnline:'Online for',offlineFor:'Offline for',edit:'Edit',del:'Delete',disable:'Disable',enable:'Enable',cancel:'Cancel',save:'Save',close:'Close',addT:'Add MAC',editT:'Edit device',macHint:'MAC is normalized to AA-BB-CC-DD-EE-FF and synced to Windows DHCP Allow.',days:'days',hours:'hours',minutes:'min',leaseCheck:'Lease last check',next:'next',allowMode:'Allow',realtime:'real-time',denySync:'Deny last sync',duration:'duration',multi:'multiple leases',expiry:'expires',confirm:'Delete and remove from DHCP Allow/Deny?'},vi:{title:'Quản lý thiết bị DHCP MAC',sub:'Allow thời gian thực + kiểm tra Lease mỗi 5 phút + đồng bộ Deny mỗi 4 giờ',logs:'Nhật ký kiểm tra',users:'Tài khoản',export:'Xuất CSV',import:'Nhập CSV',sync:'Đồng bộ ngay',add:'+ Thêm MAC',logout:'Đăng xuất',total:'Tổng MAC quản lý',totalHint:'Bản ghi Allow và Deny',ok:'Online trong 3 ngày',okHint:'Online liên tục ≤ 3 ngày',d3:'Online quá 3 ngày',d3Hint:'Online liên tục >3 và ≤7 ngày',d7:'Online quá 7 ngày',d7Hint:'Online liên tục > 7 ngày',offline:'Hiện đang ngoại tuyến',offlineHint:'Không thấy qua 2 lần kiểm tra',never:'Chưa từng kết nối',neverHint:'Thêm rồi nhưng chưa thấy trong DHCP',disabled:'Đã tắt',disabledHint:'MAC đã chuyển sang Deny',all:'Tất cả',onlyNormal:'Online ≤3 ngày',only3:'Online >3 ngày',only7:'Online >7 ngày',onlyOffline:'Ngoại tuyến',onlyNever:'Chưa từng kết nối',onlyDisabled:'Đã tắt',legend:'Giải thích trạng thái',legendTitle:'Phân loại trạng thái',legendNormal:'Online liên tục ≤ 3 ngày',legendOver3:'Online liên tục >3 ngày và ≤7 ngày',legendOver7:'Online liên tục >7 ngày',legendOffline:'Không tìm thấy trong 2 lần kiểm tra Lease liên tiếp',legendNever:'Chưa từng tìm thấy trong DHCP Lease sau khi thêm',legendDisabled:'MAC đã được chuyển từ Allow sang Deny',legendNote:'Lưu ý: trạng thái dựa trên Windows DHCP Active Lease, không phải trạng thái vật lý từ switch hoặc bộ điều khiển Wi-Fi. Lần kiểm tra đầu tiên sau khi nâng cấp V1.6.0 sẽ tạo mốc tính thời gian online liên tục.',status:'Trạng thái',name:'Người dùng / Thiết bị',note:'Ghi chú / Allow Description',noteShort:'Ghi chú',ip:'IP cuối',scope:'Mạng',onlineSince:'Online từ lúc',lastDetected:'Phát hiện cuối',stateDuration:'Trạng thái liên tục',leaseInfo:'Thông tin Lease',creator:'Người thêm',act:'Thao tác',search:'Tìm MAC / người dùng / ghi chú / IP / tài khoản',normal:'Online trong 3 ngày',over3:'Online quá 3 ngày',over7:'Online quá 7 ngày',offlineS:'Hiện đang ngoại tuyến',neverS:'Chưa từng kết nối',disabledS:'Đã tắt',continuousOnline:'Online liên tục',offlineFor:'Ngoại tuyến',edit:'Sửa',del:'Xóa',disable:'Tắt',enable:'Bật',cancel:'Hủy',save:'Lưu',close:'Đóng',addT:'Thêm MAC',editT:'Sửa thiết bị',macHint:'MAC tự động chuyển thành AA-BB-CC-DD-EE-FF và đồng bộ vào Windows DHCP Allow.',days:'ngày',hours:'giờ',minutes:'phút',leaseCheck:'Kiểm tra Lease cuối',next:'lần tới',allowMode:'Allow',realtime:'thời gian thực',denySync:'Đồng bộ Deny cuối',duration:'thời gian',multi:'nhiều Lease',expiry:'hết hạn',confirm:'Xóa và đồng thời xóa khỏi DHCP Allow/Deny?'}};
const $=x=>document.getElementById(x);$('lang').value=lang;$('lang').onchange=e=>{lang=e.target.value;localStorage.setItem('lang',lang);apply();render()};
function t(k){return (L[lang]||L.zh)[k]||k}
function apply(){document.querySelectorAll('[data-i]').forEach(e=>e.textContent=t(e.dataset.i));document.querySelectorAll('[data-ph]').forEach(e=>e.placeholder=t(e.dataset.ph));if(!isAdmin&&$('importBtn'))$('importBtn').style.display='none';if(!canEdit){if($('addBtn'))$('addBtn').style.display='none';if($('syncBtn'))$('syncBtn').style.display='none'}}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function formatMAC(el){let x=el.value.toUpperCase().replace(/[^0-9A-F]/g,'').slice(0,12);el.value=(x.match(/.{1,2}/g)||[]).join('-')}
function spanText(days){if(days===undefined||days===null||Number(days)<0)return '-';let total=Math.max(0,Math.floor(Number(days)*24*60)),day=Math.floor(total/1440),hour=Math.floor((total%1440)/60),minute=total%60;if(day>0)return day+' '+t('days')+' '+hour+' '+t('hours');if(hour>0)return hour+' '+t('hours')+' '+minute+' '+t('minutes');return minute+' '+t('minutes')}
function durationText(d){if(d.status==='normal'||d.status==='over3'||d.status==='over7')return t('continuousOnline')+' '+spanText(d.days);if(d.status==='offline')return t('offlineFor')+' '+spanText(d.days);return '-'}
function tag(d){let map={normal:['normal','●'],over3:['over3','●'],over7:['over7','●'],offline:['offlineS','●'],never:['neverS','○'],disabled:['disabledS','⊘']},v=map[d.status]||map.never;return '<span class="statusBadge status-'+esc(d.status)+'"><span class="dot">'+v[1]+'</span><span>'+t(v[0])+'</span></span>'}
function fmtDT(v){if(!v)return '-';let d=new Date(v);return isNaN(d)?String(v):d.toLocaleString()}
function syncText(x){x=x||{};let a=[];a.push(t('leaseCheck')+': '+fmtDT(x.last_lease_check)+' / '+t('next')+': '+fmtDT(x.next_lease_check));a.push(t('allowMode')+': '+t('realtime'));a.push(t('denySync')+': '+fmtDT(x.last_deny_sync)+' / '+t('next')+': '+fmtDT(x.next_deny_sync));if(x.multi_lease_macs!==undefined&&Number(x.multi_lease_macs)>0)a.push(t('multi')+': '+x.multi_lease_macs);if(x.lease_duration_ms!==undefined)a.push(t('duration')+': '+(Number(x.lease_duration_ms)/1000).toFixed(2)+'s');return a.join('  |  ')}
async function load(){let r=await fetch('/api/devices',{cache:'no-store'});if(r.status===401){location='/login';return}let x=await r.json();devices=x.devices||[];$('syncMsg').textContent=syncText(x.sync);render()}
function render(){let q=$('q').value.toLowerCase(),n3=0,n7=0,noff=0,nn=0,nok=0,nd=0;devices.forEach(d=>{if(d.status==='disabled')nd++;else if(d.status==='never')nn++;else if(d.status==='offline')noff++;else if(d.status==='over7')n7++;else if(d.status==='over3')n3++;else nok++});$('nTotal').textContent=devices.length;$('nOk').textContent=nok;$('n3').textContent=n3;$('n7').textContent=n7;$('nOffline').textContent=noff;$('nNever').textContent=nn;$('nDisabled').textContent=nd;let arr=devices.filter(d=>{if(filter!=='all'&&d.status!==filter)return false;return !q||[d.mac,d.name,d.note,d.last_ip,d.hostname,d.scope,d.created_by].join(' ').toLowerCase().includes(q)});let totalPages=Math.max(1,Math.ceil(arr.length/pageSize));if(page>totalPages)page=totalPages;if(page<1)page=1;let start=(page-1)*pageSize,end=Math.min(start+pageSize,arr.length),pageRows=arr.slice(start,end);$('pageInfo').textContent=(arr.length?(start+1)+'-'+end:'0')+' / '+arr.length+'  ·  '+page+'/'+totalPages;$('prevBtn').disabled=page<=1;$('nextBtn').disabled=page>=totalPages;$('rows').innerHTML=pageRows.map(d=>{let ml=d.multi_lease||{},lease=Number(d.active_lease_count||0)>1?'<button class="btn soft" style="color:#c2410c" onclick="showLeases(\''+d.mac+'\')">'+(ml.mobile?'⚠ 多 Lease 人员':'⚠ '+esc(d.active_lease_count)+' Lease')+'</button>':(Number(d.active_lease_count||0)===1?'<div>1</div><div class="subline">'+t('expiry')+': '+fmtDT(d.last_lease_expiry)+'</div>':'-');let actions=!canEdit?'—':'<div class="rowActions"><button class="btn" onclick="openEdit(\''+d.mac+'\')">'+t('edit')+'</button><button class="btn" onclick="toggleMac(\''+d.mac+'\','+(!d.enabled)+')">'+t(d.enabled?'disable':'enable')+'</button>'+(isAdmin?'<button class="btn danger" onclick="delMac(\''+d.mac+'\')">'+t('del')+'</button>':'')+'</div>';return '<tr><td>'+tag(d)+'</td><td><b>'+esc(d.mac)+'</b></td><td>'+esc(d.name||'-')+'</td><td>'+esc(d.note||'-')+'</td><td>'+esc(d.last_ip||'-')+'</td><td>'+esc(d.scope||'-')+'</td><td>'+fmtDT(d.online_since)+'</td><td>'+fmtDT(d.last_detected||d.last_seen)+'</td><td><span class="duration '+esc(d.status)+'">'+esc(durationText(d))+'</span></td><td>'+lease+'</td><td>'+esc(d.created_by||'-')+'</td><td>'+actions+'</td></tr>'}).join('')||'<tr><td colspan="12" class="muted" style="text-align:center;padding:34px">-</td></tr>'}
function showLeases(mac){let d=devices.find(x=>x.mac===mac);if(!d||!d.active_leases||!d.active_leases.length)return;let lines=d.active_leases.map(x=>(x.ip||'-')+' | Scope '+(x.scope||'-')+' | '+fmtDT(x.lease_expiry)+' | '+(x.address_state||'-')),m=d.multi_lease||{},history=(m.observations||[]).map(x=>fmtDT(x.time)+' → '+x.reachable_ip+' / '+x.scope);alert(mac+'\n\n'+(m.mobile?'⚠ 多 Lease 人员\n自动释放：已暂停\n切换次数：'+(m.switches||0):'⚠ '+d.active_lease_count+' Lease\n30分钟确认中')+'\n\n'+lines.join('\n')+(history.length?'\n\n切换历史：\n'+history.join('\n'):''))}
function setFilter(f,b){filter=f;page=1;document.querySelectorAll('.tabs .btn').forEach(x=>x.classList.remove('activeTab'));b.classList.add('activeTab');render()}
function changePage(delta){page+=delta;render()}function setPageSize(v){pageSize=Number(v)||100;page=1;render()}
function openAdd(){if(!canEdit)return;editMac='';$('mTitle').textContent=t('addT');$('mMac').value='';$('mMac').disabled=false;$('mName').value='';$('mNote').value='';$('modal').classList.add('show')}
function openEdit(mac){let d=devices.find(x=>x.mac===mac);if(!d)return;editMac=mac;$('mTitle').textContent=t('editT');$('mMac').value=d.mac;$('mMac').disabled=true;$('mName').value=d.name||'';$('mNote').value=d.note||'';$('modal').classList.add('show')}
function closeModal(){$('modal').classList.remove('show')}function openLegend(){$('legendModal').classList.add('show')}function closeLegend(){$('legendModal').classList.remove('show')}
async function saveModal(){let body={MAC:$('mMac').value,Name:$('mName').value,Note:$('mNote').value};let r=await fetch(editMac?'/api/update':'/api/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});let x=await r.json();if(!r.ok){alert(x.error||'Error');return}closeModal();await load()}
async function delMac(mac){if(!isAdmin)return;if(!confirm(t('confirm')))return;let r=await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({MAC:mac})});let x=await r.json();if(!r.ok){alert(x.error||'Error');return}load()}
async function deleteDisabled(){if(!isAdmin||!confirm('确认删除全部已停用 MAC？每个设备都会进入回收站。'))return;let r=await fetch('/api/devices/delete-disabled',{method:'POST'}),x=await r.json();alert('成功: '+(x.success||0)+'\n失败: '+((x.failed||[]).length));load()}
async function showRecycle(){if(!isAdmin)return;let r=await fetch('/api/recycle'),x=await r.json(),items=x.items||[];if(!items.length){alert('回收站为空');return}let mac=prompt('回收站（共 '+items.length+' 条）\n'+items.slice(-20).reverse().map(v=>v.snapshot.mac+' | '+v.deleted_at+' | '+v.deleted_by).join('\n')+'\n\n输入要恢复的 MAC：');if(!mac)return;let rr=await fetch('/api/recycle/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({MAC:mac})}),y=await rr.json();if(!rr.ok)alert(y.error||'恢复失败');else alert(y.reservation_restored?'已完整恢复（含固定 IP）':'MAC 已恢复；固定 IP 若冲突则未恢复');load()}
async function toggleMac(mac,enabled){let r=await fetch('/api/device/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({MAC:mac,Enabled:enabled})});let x=await r.json();if(!r.ok){alert(x.error||'Error');return}load()}
async function syncNow(){if(!canEdit)return;let r=await fetch('/api/sync',{method:'POST'});let x=await r.json();if(!r.ok)alert(x.message||x.error||'Error');load()}
async function importCSV(inp){if(!isAdmin)return;if(!inp.files.length)return;let fd=new FormData();fd.append('file',inp.files[0]);let r=await fetch('/api/import',{method:'POST',body:fd});let x=await r.json();alert(r.ok?'Imported: '+x.imported+', skipped: '+x.skipped:(x.error||'Error'));inp.value='';if(r.ok)load()}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeModal();closeLegend()}});apply();load();setInterval(load,60000);
</script></body></html>`))

var reservationsTpl = template.Must(template.New("reservations").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>固定 IP / Reservations</title><style>` + baseCSS + `</style></head><body><div class="wrap"><div class="top"><div><h1>固定 IP / Reservation / VLAN</h1><div class="muted">全部 IPv4 Scope 独立显示；保存前检查范围与冲突。Signed in: {{.Username}}</div></div><a class="btn" href="/">返回主页</a></div>{{if .CanEdit}}<div class="panel" style="margin-top:18px;padding:18px"><h2>添加固定 IP</h2><div class="tools"><input id="mac" placeholder="MAC AA-BB-CC-DD-EE-FF"><select id="scope"></select><input id="ip" placeholder="固定 IP"><input id="name" placeholder="名称"><input id="vlan" placeholder="VLAN/备注"><button class="btn primary" onclick="save()">检查并绑定</button></div><div class="muted">若 MAC 已停用，绑定前会自动 Deny → Allow。已有 Reservation、IP 范围、Reservation 冲突及 Active Lease 冲突均会检查。</div></div>{{end}}<div id="msg" class="muted" style="margin:16px 0">正在读取 DHCP Scopes…</div><div id="content"></div></div><script>const canEdit={{if .CanEdit}}true{{else}}false{{end}};let data={scopes:[],reservations:[]};const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function load(){let r=await fetch('/api/reservations'),x=await r.json();if(!r.ok){document.getElementById('msg').textContent=x.error||'读取失败';return}data=x;document.getElementById('msg').textContent='Scope: '+data.scopes.length+'；Reservation: '+data.reservations.length;if(canEdit)document.getElementById('scope').innerHTML=data.scopes.map(s=>'<option value="'+e(s.scope)+'">'+e(s.scope)+' | '+e(s.name)+' | '+e(s.start)+' - '+e(s.end)+'</option>').join('');render()}function render(){document.getElementById('content').innerHTML=data.scopes.map(s=>{let rs=data.reservations.filter(r=>r.scope===s.scope);return '<div class="panel" style="margin:14px 0"><div class="tools"><b>'+e(s.scope)+' · '+e(s.name||s.vlan||'VLAN')+'</b><span class="muted">'+e(s.start)+' - '+e(s.end)+' / '+e(s.mask)+' · '+e(s.state)+'</span></div><div class="tableWrap" style="min-height:0;max-height:380px"><table><thead><tr><th>IP</th><th>MAC</th><th>名称</th><th>说明/VLAN</th><th>操作</th></tr></thead><tbody>'+rs.map(r=>'<tr><td><b>'+e(r.ip)+'</b></td><td>'+e(r.mac)+'</td><td>'+e(r.name||'-')+'</td><td>'+e(r.description||'-')+'</td><td>'+(canEdit?'<button class="btn" onclick=\'edit('+JSON.stringify(JSON.stringify(r))+')\'>修改</button> <button class="btn danger" onclick=\'del('+JSON.stringify(JSON.stringify(r))+')\'>删除</button>':'—')+'</td></tr>').join('')+(rs.length?'':'<tr><td colspan="5" class="muted">此 Scope 暂无 Reservation</td></tr>')+'</tbody></table></div></div>'}).join('')}function edit(j){let r=JSON.parse(j);document.getElementById('mac').value=r.mac;document.getElementById('scope').value=r.scope;document.getElementById('ip').value=r.ip;document.getElementById('name').value=r.name||'';document.getElementById('vlan').value=r.description||'';scrollTo(0,0);alert('修改 Reservation：请先删除原记录，再以新 IP/Scope 保存。')}async function del(j){let q=JSON.parse(j);if(!confirm('删除固定 IP '+q.ip+' ?'))return;let r=await fetch('/api/reservation/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(q)}),x=await r.json();if(!r.ok)alert(x.error);else load()}async function save(){let q={MAC:document.getElementById('mac').value,Scope:document.getElementById('scope').value,IP:document.getElementById('ip').value,Name:document.getElementById('name').value,VLAN:document.getElementById('vlan').value};let r=await fetch('/api/reservation',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(q)}),x=await r.json();if(!r.ok)alert(x.error||'保存失败');else{alert('固定 IP 已创建');load()}}load()</script></body></html>`))

var recycleTpl = template.Must(template.New("recycle").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MAC 回收站</title><style>` + baseCSS + `</style></head><body><div class="wrap"><div class="top"><div><h1>MAC 回收站</h1><div class="muted">仅 admin 可见 · 完整删除快照与 Reservation 恢复</div></div><a class="btn" href="/">返回主页</a></div><div class="panel" style="margin-top:18px"><div class="tools"><input id="q" placeholder="搜索 MAC / 用户名 / 删除账号" oninput="render()"><span id="count" class="muted"></span></div><div class="tableWrap"><table><thead><tr><th>删除时间</th><th>MAC</th><th>用户名/设备名</th><th>删除前状态</th><th>固定 IP</th><th>删除账号</th><th>原因</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table></div></div></div><script>let items=[];const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function load(){let r=await fetch('/api/recycle'),x=await r.json();if(!r.ok){location='/';return}items=(x.items||[]).reverse();render()}function render(){let q=document.getElementById('q').value.toLowerCase(),a=items.filter(x=>!q||[x.snapshot.mac,x.snapshot.name,x.deleted_by,x.reason].join(' ').toLowerCase().includes(q));document.getElementById('count').textContent=a.length+' 条';document.getElementById('rows').innerHTML=a.map(x=>'<tr><td>'+new Date(x.deleted_at).toLocaleString()+'</td><td><b>'+e(x.snapshot.mac)+'</b></td><td>'+e(x.snapshot.name||'-')+'</td><td>'+(x.snapshot.disabled?'已停用':'启用')+'</td><td>'+e(x.snapshot.reservation?x.snapshot.reservation.ip:'-')+'</td><td>'+e(x.deleted_by)+'</td><td>'+e(x.reason)+'</td><td><button class="btn primary" onclick="restore(\''+e(x.snapshot.mac)+'\')">恢复完整快照</button></td></tr>').join('')||'<tr><td colspan="8" class="muted">回收站为空</td></tr>'}async function restore(mac){if(!confirm('恢复 '+mac+' 及其完整资料和固定 IP？'))return;let r=await fetch('/api/recycle/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({MAC:mac})}),x=await r.json();if(!r.ok)alert(x.error||'恢复失败');else{alert(x.reservation_restored?'恢复成功（含固定 IP）':'MAC 已恢复；原固定 IP 冲突或恢复失败，请重新绑定');load()}}load()</script></body></html>`))

var reservationsPageTpl2 = template.Must(template.New("reservations2").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Fixed IP / Reservation / VLAN</title><style>` + baseCSS + layoutFixCSS + `</style></head><body><div class="wrap"><div class="top"><div class="brand"><h1 data-i="title"></h1><div class="muted"><span data-i="subtitle"></span> · {{.Username}}</div></div><div class="nav"><select id="lang"><option value="zh">中文</option><option value="en">English</option><option value="vi">Tiếng Việt</option></select><a class="btn" href="/" data-i="back"></a></div></div>{{if .CanEdit}}<section class="panel" style="margin-top:18px;padding:20px"><h2 data-i="addTitle"></h2><div class="reservationForm"><input id="mac" data-ph="mac"><select id="scope"></select><input id="ip" data-ph="ip"><input id="name" data-ph="name"><input id="vlan" data-ph="vlan"><button class="btn primary" onclick="save()" data-i="bind"></button></div><div class="muted" style="margin-top:12px" data-i="helper"></div></section>{{end}}<div id="msg" class="muted" style="margin:16px 0"></div><div id="content"></div></div><script>const canEdit={{if .CanEdit}}true{{else}}false{{end}},L={zh:{title:'固定 IP / Reservation / VLAN',subtitle:'全部 IPv4 Scope 独立显示，保存前检查范围与冲突',back:'返回主页',addTitle:'添加固定 IP',mac:'MAC 地址',ip:'固定 IP',name:'名称',vlan:'VLAN / 备注',bind:'检查并绑定',helper:'若 MAC 已停用，绑定前会自动 Deny → Allow。系统检查 IP 范围、已有 Reservation、Reservation 冲突和 Active Lease 冲突。',loading:'正在读取 DHCP Scope…',readFail:'读取失败',scopeCount:'Scope',reservationCount:'Reservation',colIP:'IP',colMAC:'MAC',colName:'名称',colDesc:'说明 / VLAN',colAction:'操作',edit:'修改',del:'删除',empty:'此 Scope 暂无 Reservation',editHelp:'请先删除原 Reservation，再使用新 IP 或 Scope 保存。',deleteAsk:'确认删除固定 IP',saveOK:'固定 IP 已创建',saveFail:'保存失败'},en:{title:'Fixed IP / Reservation / VLAN',subtitle:'All IPv4 scopes, with range and conflict checks before saving',back:'Dashboard',addTitle:'Add fixed IP',mac:'MAC address',ip:'Fixed IP',name:'Name',vlan:'VLAN / note',bind:'Check and bind',helper:'A disabled MAC is enabled first (Deny → Allow). Scope range, existing reservations and active-lease conflicts are checked.',loading:'Loading DHCP scopes…',readFail:'Unable to load',scopeCount:'Scopes',reservationCount:'Reservations',colIP:'IP',colMAC:'MAC',colName:'Name',colDesc:'Description / VLAN',colAction:'Actions',edit:'Edit',del:'Delete',empty:'No reservations in this scope',editHelp:'Delete the old reservation first, then save the new IP or scope.',deleteAsk:'Delete fixed IP',saveOK:'Fixed IP created',saveFail:'Unable to save'},vi:{title:'IP cố định / Reservation / VLAN',subtitle:'Hiển thị từng IPv4 Scope và kiểm tra phạm vi, xung đột trước khi lưu',back:'Trang chính',addTitle:'Thêm IP cố định',mac:'Địa chỉ MAC',ip:'IP cố định',name:'Tên',vlan:'VLAN / ghi chú',bind:'Kiểm tra và gán',helper:'MAC bị tắt sẽ được bật trước (Deny → Allow). Hệ thống kiểm tra Scope, Reservation và xung đột Active Lease.',loading:'Đang tải DHCP Scope…',readFail:'Không thể tải',scopeCount:'Scope',reservationCount:'Reservation',colIP:'IP',colMAC:'MAC',colName:'Tên',colDesc:'Mô tả / VLAN',colAction:'Thao tác',edit:'Sửa',del:'Xóa',empty:'Scope này chưa có Reservation',editHelp:'Hãy xóa Reservation cũ trước, sau đó lưu IP hoặc Scope mới.',deleteAsk:'Xóa IP cố định',saveOK:'Đã tạo IP cố định',saveFail:'Không thể lưu'}};let lang=localStorage.getItem('lang')||'zh',data={scopes:[],reservations:[]};const $=x=>document.getElementById(x),t=k=>L[lang][k]||L.zh[k]||k,e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function apply(){document.documentElement.lang=lang==='zh'?'zh-CN':lang;document.querySelectorAll('[data-i]').forEach(x=>x.textContent=t(x.dataset.i));document.querySelectorAll('[data-ph]').forEach(x=>x.placeholder=t(x.dataset.ph));$('msg').textContent=data.scopes.length?t('scopeCount')+': '+data.scopes.length+' · '+t('reservationCount')+': '+data.reservations.length:t('loading');render()}$('lang').value=lang;$('lang').onchange=x=>{lang=x.target.value;localStorage.setItem('lang',lang);apply()};async function load(){apply();let r=await fetch('/api/reservations'),x=await r.json();if(!r.ok){$('msg').textContent=t('readFail')+': '+(x.error||'');return}data=x;if(canEdit)$('scope').innerHTML=data.scopes.map(s=>'<option value="'+e(s.scope)+'">'+e(s.scope)+' | '+e(s.name)+' | '+e(s.start)+' - '+e(s.end)+'</option>').join('');apply()}function render(){$('content').innerHTML=data.scopes.map(s=>{let rs=data.reservations.filter(r=>r.scope===s.scope);return '<section class="panel scopePanel" style="margin:14px 0"><div class="tools"><b>'+e(s.scope)+' · '+e(s.name||s.vlan||'VLAN')+'</b><span class="muted">'+e(s.start)+' - '+e(s.end)+' / '+e(s.mask)+' · '+e(s.state)+'</span></div><div class="tableWrap"><table><thead><tr><th>'+t('colIP')+'</th><th>'+t('colMAC')+'</th><th>'+t('colName')+'</th><th>'+t('colDesc')+'</th><th>'+t('colAction')+'</th></tr></thead><tbody>'+rs.map(r=>'<tr><td><b>'+e(r.ip)+'</b></td><td>'+e(r.mac)+'</td><td>'+e(r.name||'-')+'</td><td>'+e(r.description||'-')+'</td><td>'+(canEdit?'<button class="btn" onclick=\'edit('+JSON.stringify(JSON.stringify(r))+')\'>'+t('edit')+'</button> <button class="btn danger" onclick=\'del('+JSON.stringify(JSON.stringify(r))+')\'>'+t('del')+'</button>':'—')+'</td></tr>').join('')+(rs.length?'':'<tr><td colspan="5" class="muted">'+t('empty')+'</td></tr>')+'</tbody></table></div></section>'}).join('')}function edit(j){let r=JSON.parse(j);$('mac').value=r.mac;$('scope').value=r.scope;$('ip').value=r.ip;$('name').value=r.name||'';$('vlan').value=r.description||'';scrollTo(0,0);alert(t('editHelp'))}async function del(j){let q=JSON.parse(j);if(!confirm(t('deleteAsk')+' '+q.ip+'?'))return;let r=await fetch('/api/reservation/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(q)}),x=await r.json();if(!r.ok)alert(x.error);else load()}async function save(){let q={MAC:$('mac').value,Scope:$('scope').value,IP:$('ip').value,Name:$('name').value,VLAN:$('vlan').value};let r=await fetch('/api/reservation',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(q)}),x=await r.json();if(!r.ok)alert(x.error||t('saveFail'));else{alert(t('saveOK'));load()}}load()</script></body></html>`))

var recyclePageTpl2 = template.Must(template.New("recycle2").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MAC Recycle Bin</title><style>` + baseCSS + layoutFixCSS + `</style></head><body><div class="wrap"><div class="top"><div class="brand"><h1 data-i="title"></h1><div class="muted" data-i="subtitle"></div></div><div class="nav"><select id="lang"><option value="zh">中文</option><option value="en">English</option><option value="vi">Tiếng Việt</option></select><a class="btn" href="/" data-i="back"></a></div></div><div class="panel" style="margin-top:18px"><div class="tools"><input id="q" data-ph="search" oninput="render()"><span id="count" class="muted"></span></div><div class="tableWrap"><table style="min-width:1100px"><thead><tr><th data-i="deletedAt"></th><th>MAC</th><th data-i="device"></th><th data-i="before"></th><th data-i="fixed"></th><th data-i="deletedBy"></th><th data-i="reason"></th><th data-i="action"></th></tr></thead><tbody id="rows"></tbody></table></div></div></div><script>const L={zh:{title:'MAC 回收站',subtitle:'仅 admin 可见 · 完整删除快照与 Reservation 恢复',back:'返回主页',search:'搜索 MAC / 用户名 / 删除账号',deletedAt:'删除时间',device:'用户名/设备名',before:'删除前状态',fixed:'固定 IP',deletedBy:'删除账号',reason:'原因',action:'操作',disabled:'已停用',enabled:'启用',restore:'恢复完整快照',empty:'回收站为空',items:'条',ask:'恢复完整资料和固定 IP？',okFixed:'恢复成功（含固定 IP）',okNoFixed:'MAC 已恢复；原固定 IP 冲突或恢复失败，请重新绑定',failed:'恢复失败'},en:{title:'MAC Recycle Bin',subtitle:'Admin only · complete snapshots and reservation recovery',back:'Dashboard',search:'Search MAC / device / deleted by',deletedAt:'Deleted at',device:'User / device',before:'Previous status',fixed:'Fixed IP',deletedBy:'Deleted by',reason:'Reason',action:'Actions',disabled:'Disabled',enabled:'Enabled',restore:'Restore snapshot',empty:'Recycle bin is empty',items:'items',ask:'Restore full details and fixed IP?',okFixed:'Restored, including fixed IP',okNoFixed:'MAC restored; fixed IP conflicted or could not be restored',failed:'Restore failed'},vi:{title:'Thùng rác MAC',subtitle:'Chỉ admin · khôi phục ảnh chụp đầy đủ và Reservation',back:'Trang chính',search:'Tìm MAC / thiết bị / người xóa',deletedAt:'Thời gian xóa',device:'Người dùng / thiết bị',before:'Trạng thái trước',fixed:'IP cố định',deletedBy:'Người xóa',reason:'Lý do',action:'Thao tác',disabled:'Đã tắt',enabled:'Đang bật',restore:'Khôi phục đầy đủ',empty:'Thùng rác trống',items:'mục',ask:'Khôi phục đầy đủ và IP cố định?',okFixed:'Đã khôi phục gồm IP cố định',okNoFixed:'Đã khôi phục MAC; IP cố định bị xung đột hoặc không thể khôi phục',failed:'Khôi phục thất bại'}};let lang=localStorage.getItem('lang')||'zh',items=[];const $=x=>document.getElementById(x),t=k=>L[lang][k]||L.zh[k]||k,e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function apply(){document.querySelectorAll('[data-i]').forEach(x=>x.textContent=t(x.dataset.i));document.querySelectorAll('[data-ph]').forEach(x=>x.placeholder=t(x.dataset.ph));render()}$('lang').value=lang;$('lang').onchange=x=>{lang=x.target.value;localStorage.setItem('lang',lang);apply()};async function load(){let r=await fetch('/api/recycle'),x=await r.json();if(!r.ok){location='/';return}items=(x.items||[]).reverse();apply()}function render(){let q=$('q').value.toLowerCase(),a=items.filter(x=>!q||[x.snapshot.mac,x.snapshot.name,x.deleted_by,x.reason].join(' ').toLowerCase().includes(q));$('count').textContent=a.length+' '+t('items');$('rows').innerHTML=a.map(x=>'<tr><td>'+new Date(x.deleted_at).toLocaleString()+'</td><td><b>'+e(x.snapshot.mac)+'</b></td><td>'+e(x.snapshot.name||'-')+'</td><td>'+t(x.snapshot.disabled?'disabled':'enabled')+'</td><td>'+e(x.snapshot.reservation?x.snapshot.reservation.ip:'-')+'</td><td>'+e(x.deleted_by)+'</td><td>'+e(x.reason)+'</td><td><button class="btn primary" onclick="restore(\''+e(x.snapshot.mac)+'\')">'+t('restore')+'</button></td></tr>').join('')||'<tr><td colspan="8" class="muted">'+t('empty')+'</td></tr>'}async function restore(mac){if(!confirm(mac+' · '+t('ask')))return;let r=await fetch('/api/recycle/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({MAC:mac})}),x=await r.json();if(!r.ok)alert(x.error||t('failed'));else{alert(x.reservation_restored?t('okFixed'):t('okNoFixed'));load()}}load()</script></body></html>`))

var logsTpl = template.Must(template.New("logs").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Audit Logs</title><style>` + baseCSS + layoutFixCSS + `</style></head><body><div class="wrap"><div class="top"><div><h1>Audit Logs / 审核日志 / Nhật ký</h1><div class="muted">Signed in: {{.Username}}</div></div><div><a class="btn" href="/">Dashboard</a> <a class="btn" href="/api/export">Export MAC CSV</a></div></div><div class="panel" style="margin-top:20px"><div class="tools"><input id="q" placeholder="Search user / action / MAC / detail" oninput="render()"></div><div class="tableWrap"><table><thead><tr><th>Time</th><th>Account</th><th>Action</th><th>MAC</th><th>Detail</th><th>Client IP</th></tr></thead><tbody id="rows"></tbody></table></div></div></div><script>let logs=[];const $=x=>document.getElementById(x);function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function load(){let r=await fetch('/api/logs');if(r.status===401||r.status===403){location='/';return}let x=await r.json();logs=x.logs||[];render()}function render(){let q=$('q').value.toLowerCase();$('rows').innerHTML=logs.filter(x=>!q||[x.username,x.action,x.mac,x.detail,x.client_ip].join(' ').toLowerCase().includes(q)).map(x=>'<tr><td>'+new Date(x.time).toLocaleString()+'</td><td><b>'+esc(x.username)+'</b></td><td>'+esc(x.action)+'</td><td>'+esc(x.mac||'-')+'</td><td>'+esc(x.detail)+'</td><td>'+esc(x.client_ip)+'</td></tr>').join('')}load()</script></body></html>`))

var usersTpl = template.Must(template.New("users").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Accounts</title><style>` + baseCSS + `</style></head><body><div class="wrap"><div class="top"><div><h1>Account Management / 账号管理</h1><div class="muted">admin / operator / viewer</div></div><a class="btn" href="/">Dashboard</a></div><div class="panel" style="margin-top:20px"><div class="tools"><button class="btn primary" onclick="addUser()">+ Add account</button></div><div class="tableWrap"><table><thead><tr><th>Username</th><th>Role</th><th>Enabled</th><th>Created by</th><th>Created at</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table></div></div></div><script>let users=[];function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function load(){let r=await fetch('/api/users');if(!r.ok){location='/';return}let x=await r.json();users=x.users||[];document.getElementById('rows').innerHTML=users.map(u=>'<tr><td><b>'+esc(u.username)+'</b></td><td>'+esc(u.role)+'</td><td>'+(u.enabled?'Yes':'No')+'</td><td>'+esc(u.created_by)+'</td><td>'+new Date(u.created_at).toLocaleString()+'</td><td><button class="btn" onclick="resetPw(\''+esc(u.username)+'\')">Reset password</button> <button class="btn" onclick="changeRole(\''+esc(u.username)+'\',\''+esc(u.role)+'\')">Change role</button> <button class="btn" onclick="toggle(\''+esc(u.username)+'\','+(!u.enabled)+')">'+(u.enabled?'Disable':'Enable')+'</button> <button class="btn danger" onclick="delUser(\''+esc(u.username)+'\')">Delete</button></td></tr>').join('')}async function addUser(){let username=prompt('Username');if(!username)return;let password=prompt('Password (8+)');if(!password)return;let role=prompt('Role: admin / operator / viewer','operator')||'operator';let r=await fetch('/api/users/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Username:username,Password:password,Role:role})});let x=await r.json();if(!r.ok)alert(x.error);load()}async function resetPw(username){let password=prompt('New password (8+)');if(!password)return;let r=await fetch('/api/users/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Username:username,Password:password})});let x=await r.json();if(!r.ok)alert(x.error);else alert('OK')}async function changeRole(username,current){let role=prompt('Role: admin / operator / viewer',current);if(!role)return;let r=await fetch('/api/users/role',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Username:username,Role:role})});let x=await r.json();if(!r.ok)alert(x.error);load()}async function delUser(username){if(!confirm('Delete account '+username+'?'))return;let r=await fetch('/api/users/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Username:username})});let x=await r.json();if(!r.ok)alert(x.error);load()}async function toggle(username,enabled){let r=await fetch('/api/users/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({Username:username,Enabled:enabled})});let x=await r.json();if(!r.ok)alert(x.error);load()}load()</script></body></html>`))
