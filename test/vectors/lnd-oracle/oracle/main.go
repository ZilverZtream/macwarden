// LND v0.21.4 macaroon oracle: same go-macaroon (v2.0.0), bakery (v2.0.1) and
// protobuf (lightninglabs fork) versions as LND's go.mod, and a copy of
// macaroons.Service.CheckMacAuth's structure checks plus LND's constraint
// checkers. Reads one request per line on stdin, writes one JSON line per request.
//
//	M <hex macaroon>      -> parse/ops/conditions/auth facts
//	T <string>            -> time.Parse(RFC3339Nano) result (unix nanos)
//	I <string>            -> net.ParseIP / net.ParseCIDR canonical forms
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/peer"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	macaroon "gopkg.in/macaroon.v2"
)

var rootKey = []byte("macwarden-fuzz-root-key-0123456")

type store struct{ last []byte }

func (s *store) Get(_ context.Context, id []byte) ([]byte, error) {
	s.last = append([]byte(nil), id...)
	// LND's bucket holds "0" and strconv.FormatUint IDs (plus "enckey", whose
	// value does not decrypt as a root key). Anything else is not found.
	if _, err := strconv.ParseUint(string(id), 10, 64); err != nil || strconv.FormatUint(mustU(id), 10) != string(id) {
		return nil, bakery.ErrNotFound
	}
	return rootKey, nil
}
func (s *store) RootKey(context.Context) ([]byte, []byte, error) { return rootKey, []byte("0"), nil }

func mustU(id []byte) uint64 { v, _ := strconv.ParseUint(string(id), 10, 64); return v }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// Copies of lnd v0.21.4 macaroons/constraints.go checkers.
func ipLock() (string, checkers.Func) {
	return "ipaddr", func(ctx context.Context, cond, arg string) error {
		pr, ok := peer.FromContext(ctx)
		if !ok {
			return fmt.Errorf("unable to get peer info from context")
		}
		peerAddr, _, err := net.SplitHostPort(pr.Addr.String())
		if err != nil {
			return fmt.Errorf("unable to parse peer address")
		}
		if !net.ParseIP(arg).Equal(net.ParseIP(peerAddr)) {
			return fmt.Errorf("macaroon locked to different IP address")
		}
		return nil
	}
}
func ipRange() (string, checkers.Func) {
	return "iprange", func(ctx context.Context, cond, arg string) error {
		pr, ok := peer.FromContext(ctx)
		if !ok {
			return errors.New("unable to get peer info from context")
		}
		peerAddr, _, err := net.SplitHostPort(pr.Addr.String())
		if err != nil {
			return fmt.Errorf("unable to parse peer address: %w", err)
		}
		_, ipNet, err := net.ParseCIDR(arg)
		if err != nil {
			return fmt.Errorf("unable to parse macaroon IP range: %w", err)
		}
		if !ipNet.Contains(net.ParseIP(peerAddr)) {
			return errors.New("macaroon locked to different IP range")
		}
		return nil
	}
}

var customAccept = os.Getenv("ORACLE_CUSTOM_ACCEPT") // name of a registered middleware caveat, if any

func custom() (string, checkers.Func) {
	return "lnd-custom", func(_ context.Context, _, outer string) error {
		if outer != strings.TrimSpace(outer) {
			return fmt.Errorf("unexpected white space found in custom caveat")
		}
		if outer == "" {
			return fmt.Errorf("expected custom caveat, got empty string")
		}
		parts := strings.Split(outer, " ")
		if customAccept != "" && parts[0] == customAccept {
			return nil
		}
		return fmt.Errorf("cannot accept macaroon with custom caveat %s", parts[0])
	}
}

type cav struct {
	Loc string `json:"loc"`
	ID  string `json:"id"`
	VID string `json:"vid"`
}
type result struct {
	Parse      bool              `json:"parse"`
	Err        string            `json:"err,omitempty"`
	Location   string            `json:"location"`
	ID0        int               `json:"id0"`
	IDHex      string            `json:"idHex"`
	SigHex     string            `json:"sigHex"`
	CanonHex   string            `json:"canonHex"`
	Cavs       []cav             `json:"cavs"`
	Verify     bool              `json:"verify"`
	VerifyErr  string            `json:"verifyErr,omitempty"`
	StorageID  string            `json:"storageId"`
	Ops        []string          `json:"ops"`
	Conditions []string          `json:"conditions"`
	CondOK     []bool            `json:"condOk"`
	Allow      map[string]bool   `json:"allow"`
	TimeBefore map[string]string `json:"timeBefore,omitempty"`
}

var probeOps = []string{"info:read", "offchain:write", "onchain:write", "macaroon:generate", "invoices:write", "uri:/lnrpc.Lightning/GetInfo"}

func ctxFor(nowNanos int64) context.Context {
	ctx := checkers.ContextWithClock(context.Background(), fixedClock{time.Unix(0, nowNanos).UTC()})
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	return peer.NewContext(ctx, &peer.Peer{Addr: addr})
}

func doMacaroon(hexText string, now int64) result {
	r := result{Allow: map[string]bool{}}
	data, err := hex.DecodeString(hexText)
	if err != nil {
		r.Err = "hex: " + err.Error()
		return r
	}
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(data); err != nil {
		r.Err = err.Error()
		return r
	}
	r.Parse = true
	r.Location = mac.Location()
	r.IDHex = hex.EncodeToString(mac.Id())
	sig := mac.Signature()
	r.SigHex = hex.EncodeToString(sig[:])
	if canon, err := mac.MarshalBinary(); err == nil {
		r.CanonHex = hex.EncodeToString(canon)
	}
	if len(mac.Id()) > 0 {
		r.ID0 = int(mac.Id()[0])
	} else {
		r.ID0 = -1
	}
	for _, c := range mac.Caveats() {
		r.Cavs = append(r.Cavs, cav{c.Location, hex.EncodeToString(c.Id), hex.EncodeToString(c.VerificationId)})
	}
	if mac.Version() != macaroon.V2 || len(mac.Id()) < 1 || mac.Id()[0] != byte(bakery.Version3) {
		r.VerifyErr = "lnd CheckMacAuth version/id check"
		return r
	}
	st := &store{}
	b := bakery.New(bakery.BakeryParams{Location: "lnd", RootKeyStore: st})
	ch := b.Checker.FirstPartyCaveatChecker.(*checkers.Checker)
	for _, f := range []func() (string, checkers.Func){ipLock, custom, ipRange} {
		c, fn := f()
		ch.Register(c, "std", fn)
	}
	ctx := ctxFor(now)
	ops, conds, err := b.Oven.VerifyMacaroon(ctx, macaroon.Slice{mac})
	r.StorageID = hex.EncodeToString(st.last)
	if err != nil {
		r.VerifyErr = err.Error()
		return r
	}
	r.Verify = true
	for _, op := range ops {
		r.Ops = append(r.Ops, op.Entity+":"+op.Action)
	}
	r.Conditions = conds
	for _, c := range conds {
		r.CondOK = append(r.CondOK, ch.CheckFirstPartyCaveat(ctx, c) == nil)
	}
	for _, p := range probeOps {
		i := strings.IndexByte(p, ':')
		auth := b.Checker.Auth(macaroon.Slice{mac})
		_, err := auth.Allow(ctx, bakery.Op{Entity: p[:i], Action: p[i+1:]})
		r.Allow[p] = err == nil
	}
	return r
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC).UnixNano()
	for in.Scan() {
		line := in.Text()
		switch {
		case strings.HasPrefix(line, "M "):
			enc.Encode(doMacaroon(line[2:], now))
		case strings.HasPrefix(line, "T "):
			raw, _ := hex.DecodeString(line[2:])
			t, err := time.Parse(time.RFC3339Nano, string(raw))
			if err != nil {
				enc.Encode(map[string]any{"ok": false})
			} else {
				enc.Encode(map[string]any{"ok": true, "ns": fmt.Sprint(t.UnixNano()), "sec": fmt.Sprint(t.Unix()), "nsec": t.Nanosecond()})
			}
		case strings.HasPrefix(line, "I "):
			raw, _ := hex.DecodeString(line[2:])
			s := string(raw)
			res := map[string]any{}
			if ip := net.ParseIP(s); ip != nil {
				res["ip"] = ip.String()
			}
			if _, n, err := net.ParseCIDR(s); err == nil {
				res["cidr"] = n.String()
			}
			enc.Encode(res)
		default:
			enc.Encode(map[string]any{"err": "bad request"})
		}
		out.Flush()
	}
}
