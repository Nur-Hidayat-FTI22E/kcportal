package core

import "time"

// Command represents a mutation request sent to the single state-actor
// goroutine (PD-3 — "Satu penulis"). Concrete commands are listed below;
// the marker method keeps other packages from satisfying the interface
// by accident with an unrelated type.
type Command interface {
	isCommand()
	// Name returns a short, log- and event-bus-friendly identifier.
	Name() string
}

// ApproveDevice moves a device out of the Waiting zone into its assigned
// zone once an admin has vetted it (DD-15, FR-BNC-008).
type ApproveDevice struct {
	MAC    string // canonical lower-case colon form, e.g. "aa:bb:cc:dd:ee:ff"
	ZoneID int
	Note   string
}

func (ApproveDevice) isCommand()   {}
func (ApproveDevice) Name() string { return "ApproveDevice" }

// PutZonePolicy updates a zone's forwarding/egress policy: internet
// access, explicit LAN-allow exceptions, VPN kill-switch requirement
// (§4.3 chain forward, DD-08 Profil Kantor).
type PutZonePolicy struct {
	ZoneID      int
	Internet    bool
	VPNRequired bool
	LANAllow    []LANAllowRule
}

func (PutZonePolicy) isCommand()   {}
func (PutZonePolicy) Name() string { return "PutZonePolicy" }

// LANAllowRule is one explicit inter-zone exception, e.g. POS -> printer
// LAN (§4.3 comment: "meta mark 0x02 ip daddr 10.20.2.20 tcp dport 9100 accept").
type LANAllowRule struct {
	DstIP string
	Proto string
	Port  int
}

// PutSSID updates hostapd's per-BSS configuration. It never changes which
// bridge a BSS lands on (DD-01 fixes BSS0->br-lan, BSS1->br-guest
// permanently) — only broadcast/auth-adjacent settings.
type PutSSID struct {
	BSS           string // "wlan0" (Staff) or "wlan0_1" (Guest SSID "portal")
	SSID          string
	PassphraseSet bool // true when a new passphrase was written out-of-band to the secrets store
	Hidden        bool
}

func (PutSSID) isCommand()   {}
func (PutSSID) Name() string { return "PutSSID" }

// ApplyProfile switches the device's operating profile. MVP only
// implements "cafe" (see doc header table); "sekolah"/"kantor" are
// extension points only.
type ApplyProfile struct {
	Profile string
}

func (ApplyProfile) isCommand()   {}
func (ApplyProfile) Name() string { return "ApplyProfile" }

// InstallApp requests the App Pack manager start, update, or remove a
// containerised app. Only "pos-cafe" is designed so far (§7.1 IF-03).
type InstallApp struct {
	AppID   string
	Version string
	Remove  bool
}

func (InstallApp) isCommand()   {}
func (InstallApp) Name() string { return "InstallApp" }

// AuthorizeGuest and RevokeGuest are issued by the NetCtl implementation
// (IF-01) on behalf of portal-edge. They are still routed through the
// single state actor so authed_guests never has two writers — see §7.3:
// "authed_guests | portal | via NetCtl -> state actor | nft".
type AuthorizeGuest struct {
	MAC string
	TTL time.Duration
}

func (AuthorizeGuest) isCommand()   {}
func (AuthorizeGuest) Name() string { return "AuthorizeGuest" }

// RevokeGuest removes mac from authed_guests, tears down its conntrack
// state, and (if associated) triggers a DEAUTH via hostapd's ctrl socket.
type RevokeGuest struct {
	MAC string
}

func (RevokeGuest) isCommand()   {}
func (RevokeGuest) Name() string { return "RevokeGuest" }
