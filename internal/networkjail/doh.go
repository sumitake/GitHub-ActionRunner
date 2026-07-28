package networkjail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxDoHRequestTimeout      = 30 * time.Second
	maxDoHTLSHandshakeTimeout = 10 * time.Second
	maxDoHConnectionLifetime  = 10 * time.Minute
	maxDoHIdleTimeout         = 5 * time.Minute
	maxDoHResponseBytes       = 64 << 10
	maxDoHRecords             = 64
)

type DoHRuntimeConfig struct {
	RequestTimeout      time.Duration
	TLSHandshakeTimeout time.Duration
	ConnectionLifetime  time.Duration
	IdleTimeout         time.Duration
	MaxResponseBytes    int64
	MaxRecords          int
	MinTTL              uint32
	MaxTTL              uint32
}

func (config DoHRuntimeConfig) validate() error {
	if config.RequestTimeout <= 0 ||
		config.RequestTimeout > maxDoHRequestTimeout ||
		config.TLSHandshakeTimeout <= 0 ||
		config.TLSHandshakeTimeout > maxDoHTLSHandshakeTimeout ||
		config.ConnectionLifetime <= 0 ||
		config.ConnectionLifetime > maxDoHConnectionLifetime ||
		config.IdleTimeout <= 0 ||
		config.IdleTimeout > maxDoHIdleTimeout ||
		config.MaxResponseBytes <= 0 ||
		config.MaxResponseBytes > maxDoHResponseBytes ||
		config.MaxRecords <= 0 ||
		config.MaxRecords > maxDoHRecords ||
		config.MinTTL == 0 ||
		config.MaxTTL < config.MinTTL {
		return errors.New("networkjail: doh runtime config invalid")
	}
	return nil
}

type DoHResolver struct {
	graph     DecisionGraph
	endpoint  DoHEndpoint
	config    DoHRuntimeConfig
	client    *http.Client
	transport *http.Transport
}

// PermitSequencer owns the single monotonic sequence used across every fixed
// DoH endpoint for one slot/job binding. Endpoint failover must never reset or
// fork the durable permit sequence.
type PermitSequencer struct {
	mu       sync.Mutex
	sequence PermitSequence
}

func NewPermitSequencer() *PermitSequencer {
	return &PermitSequencer{}
}

func NewDoHResolver(
	graph DecisionGraph,
	endpointIndex int,
	roots *x509.CertPool,
	literals LiteralDialer,
	permits DialPermitClient,
	slot CapacitySlotID,
	generation JobGeneration,
	config DoHRuntimeConfig,
) (*DoHResolver, error) {
	return NewDoHResolverWithSequencer(
		graph,
		endpointIndex,
		roots,
		literals,
		permits,
		slot,
		generation,
		config,
		NewPermitSequencer(),
	)
}

func NewDoHResolverWithSequencer(
	graph DecisionGraph,
	endpointIndex int,
	roots *x509.CertPool,
	literals LiteralDialer,
	permits DialPermitClient,
	slot CapacitySlotID,
	generation JobGeneration,
	config DoHRuntimeConfig,
	sequencer *PermitSequencer,
) (*DoHResolver, error) {
	if graph.digest == (Digest{}) || endpointIndex < 0 ||
		endpointIndex >= len(graph.manifest.DoHBootstrap) ||
		roots == nil || literals == nil || permits == nil ||
		slot == 0 || generation == 0 || sequencer == nil {
		return nil, errors.New("networkjail: doh resolver unavailable")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if graph.manifest.DoHOpenCap > math.MaxInt32 {
		return nil, errors.New("networkjail: doh connection cap invalid")
	}
	endpoint := graph.manifest.DoHBootstrap[endpointIndex]
	connector := &dohConnector{
		endpoint:   endpoint,
		roots:      roots.Clone(),
		literals:   literals,
		permits:    permits,
		slot:       slot,
		generation: generation,
		config:     config,
		sequencer:  sequencer,
	}
	openCap := int(graph.manifest.DoHOpenCap)
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           rejectDoHPlainDial,
		DialTLSContext:        connector.DialTLSContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          openCap,
		MaxIdleConnsPerHost:   openCap,
		MaxConnsPerHost:       openCap,
		IdleConnTimeout:       config.IdleTimeout,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.RequestTimeout,
		ExpectContinueTimeout: 0,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("networkjail: doh redirect rejected")
		},
	}
	return &DoHResolver{
		graph:     graph,
		endpoint:  endpoint,
		config:    config,
		client:    client,
		transport: transport,
	}, nil
}

func (resolver *DoHResolver) Close() {
	if resolver != nil && resolver.transport != nil {
		resolver.transport.CloseIdleConnections()
	}
}

func (resolver *DoHResolver) Resolve(
	ctx context.Context,
	rawName string,
) ([]netip.Addr, error) {
	name, err := normalizeName(rawName)
	if err != nil || name != rawName {
		return nil, errors.New("networkjail: doh name invalid")
	}
	bounded, cancel := context.WithTimeout(ctx, resolver.config.RequestTimeout)
	defer cancel()

	queryTypes := []dnsmessage.Type{dnsmessage.TypeA}
	if resolver.graph.manifest.IPFamily == PublicDualStack {
		queryTypes = append(queryTypes, dnsmessage.TypeAAAA)
	}
	var answers []netip.Addr
	for _, queryType := range queryTypes {
		current, err := resolver.query(bounded, name, queryType)
		if err != nil {
			return nil, errors.New("networkjail: doh resolution failed")
		}
		answers = append(answers, current...)
		if len(answers) > resolver.config.MaxRecords {
			return nil, errors.New("networkjail: doh answer count invalid")
		}
	}
	if len(answers) == 0 {
		return nil, errors.New("networkjail: doh answer unavailable")
	}
	for _, address := range answers {
		if !address.IsValid() || address.Zone() != "" ||
			normalizeEmbedded(address) != address ||
			!addressAllowed(
				address,
				resolver.graph.manifest.IPFamily,
				resolver.graph.manifest.DynamicDeny,
				resolver.graph.manifest.DockerHost,
			) {
			return nil, errors.New("networkjail: doh answer denied")
		}
	}
	slices.SortFunc(answers, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	for index := 1; index < len(answers); index++ {
		if answers[index-1] == answers[index] {
			return nil, errors.New("networkjail: doh answer duplicated")
		}
	}
	return answers, nil
}

func (resolver *DoHResolver) query(
	ctx context.Context,
	name string,
	queryType dnsmessage.Type,
) ([]netip.Addr, error) {
	id, err := randomDNSID()
	if err != nil {
		return nil, err
	}
	message, question, err := buildDNSQuery(name, queryType, id)
	if err != nil {
		return nil, err
	}
	endpointURL := (&url.URL{
		Scheme: "https",
		Host:   resolver.endpoint.ServerName,
		Path:   resolver.endpoint.Path,
	}).String()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpointURL,
		bytes.NewReader(message),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := resolver.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("networkjail: doh response status invalid")
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" || len(parameters) != 0 {
		return nil, errors.New("networkjail: doh response type invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(
		response.Body,
		resolver.config.MaxResponseBytes+1,
	))
	if err != nil || int64(len(raw)) == 0 ||
		int64(len(raw)) > resolver.config.MaxResponseBytes {
		return nil, errors.New("networkjail: doh response size invalid")
	}
	return parseDNSResponse(raw, id, question, resolver.config)
}

type dohConnector struct {
	endpoint   DoHEndpoint
	roots      *x509.CertPool
	literals   LiteralDialer
	permits    DialPermitClient
	slot       CapacitySlotID
	generation JobGeneration
	config     DoHRuntimeConfig
	sequencer  *PermitSequencer
}

func (connector *dohConnector) DialTLSContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	expectedAddress := net.JoinHostPort(connector.endpoint.ServerName, "443")
	if network != "tcp" || address != expectedAddress {
		return nil, errors.New("networkjail: doh transport target invalid")
	}
	for _, bootstrap := range connector.endpoint.Bootstrap {
		sequence, err := connector.sequencer.next()
		if err != nil {
			return nil, err
		}
		permit, err := connector.permits.Request(ctx, DialPermitRequest{
			SlotID:        connector.slot,
			JobGeneration: connector.generation,
			Class:         DialClassDoH,
			Sequence:      sequence,
		})
		if err != nil || !permit.validFor(connector.slot, DialClassDoH) {
			return nil, errors.New("networkjail: doh permit unavailable")
		}
		connection, err := connector.literals.DialLiteral(ctx, bootstrap, 443)
		if err != nil || connection == nil {
			if connection != nil {
				_ = connection.Close()
			}
			continue
		}
		tlsConnection := tls.Client(connection, &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    connector.roots,
			ServerName: connector.endpoint.ServerName,
			NextProtos: []string{"http/1.1"},
		})
		handshakeContext, cancel := context.WithTimeout(
			ctx,
			connector.config.TLSHandshakeTimeout,
		)
		err = tlsConnection.HandshakeContext(handshakeContext)
		cancel()
		if err != nil {
			_ = tlsConnection.Close()
			continue
		}
		if err := tlsConnection.SetDeadline(
			time.Now().Add(connector.config.ConnectionLifetime),
		); err != nil {
			_ = tlsConnection.Close()
			continue
		}
		return tlsConnection, nil
	}
	return nil, errors.New("networkjail: doh bootstrap unavailable")
}

func (sequencer *PermitSequencer) next() (PermitSequence, error) {
	if sequencer == nil {
		return 0, ErrPermitSequence
	}
	sequencer.mu.Lock()
	defer sequencer.mu.Unlock()
	if sequencer.sequence == PermitSequence(math.MaxUint64) {
		return 0, ErrPermitSequence
	}
	sequencer.sequence++
	return sequencer.sequence, nil
}

func rejectDoHPlainDial(
	context.Context,
	string,
	string,
) (net.Conn, error) {
	return nil, errors.New("networkjail: plaintext doh dial rejected")
}

func randomDNSID() (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return 0, errors.New("networkjail: dns id unavailable")
	}
	return binary.BigEndian.Uint16(raw[:]), nil
}

func buildDNSQuery(
	name string,
	queryType dnsmessage.Type,
	id uint16,
) ([]byte, dnsmessage.Question, error) {
	normalized, err := normalizeName(name)
	if err != nil || normalized != name ||
		(queryType != dnsmessage.TypeA && queryType != dnsmessage.TypeAAAA) {
		return nil, dnsmessage.Question{}, errors.New("networkjail: dns question invalid")
	}
	dnsName, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, dnsmessage.Question{}, errors.New("networkjail: dns question invalid")
	}
	question := dnsmessage.Question{
		Name:  dnsName,
		Type:  queryType,
		Class: dnsmessage.ClassINET,
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{question},
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, dnsmessage.Question{}, errors.New("networkjail: dns question invalid")
	}
	return packed, question, nil
}

func parseDNSResponse(
	raw []byte,
	id uint16,
	question dnsmessage.Question,
	config DoHRuntimeConfig,
) ([]netip.Addr, error) {
	if err := config.validate(); err != nil ||
		!dnsWireLengthExact(raw, config.MaxRecords) {
		return nil, errors.New("networkjail: dns response invalid")
	}
	var message dnsmessage.Message
	if err := message.Unpack(raw); err != nil ||
		message.ID != id || !message.Response || message.Truncated ||
		message.OpCode != 0 || message.RCode != dnsmessage.RCodeSuccess ||
		len(message.Questions) != 1 ||
		message.Questions[0] != question ||
		len(message.Answers) > config.MaxRecords ||
		len(message.Authorities) != 0 ||
		len(message.Additionals) != 0 {
		return nil, errors.New("networkjail: dns response invalid")
	}

	queryName, err := normalizedDNSName(question.Name)
	if err != nil {
		return nil, errors.New("networkjail: dns response invalid")
	}
	type addressAnswer struct {
		owner   string
		address netip.Addr
	}
	aliases := make(map[string][]string)
	addresses := make([]addressAnswer, 0, len(message.Answers))
	for _, resource := range message.Answers {
		if resource.Header.Class != dnsmessage.ClassINET ||
			resource.Header.TTL < config.MinTTL ||
			resource.Header.TTL > config.MaxTTL {
			return nil, errors.New("networkjail: dns answer invalid")
		}
		owner, err := normalizedDNSName(resource.Header.Name)
		if err != nil {
			return nil, errors.New("networkjail: dns answer invalid")
		}
		switch body := resource.Body.(type) {
		case *dnsmessage.CNAMEResource:
			target, err := normalizedDNSName(body.CNAME)
			if err != nil {
				return nil, errors.New("networkjail: dns cname invalid")
			}
			aliases[owner] = append(aliases[owner], target)
		case *dnsmessage.AResource:
			if question.Type != dnsmessage.TypeA {
				return nil, errors.New("networkjail: dns answer type invalid")
			}
			addresses = append(addresses, addressAnswer{
				owner: owner, address: netip.AddrFrom4(body.A),
			})
		case *dnsmessage.AAAAResource:
			if question.Type != dnsmessage.TypeAAAA {
				return nil, errors.New("networkjail: dns answer type invalid")
			}
			addresses = append(addresses, addressAnswer{
				owner: owner, address: netip.AddrFrom16(body.AAAA),
			})
		default:
			return nil, errors.New("networkjail: dns answer type invalid")
		}
	}
	reachable := map[string]struct{}{queryName: {}}
	for changed := true; changed; {
		changed = false
		for owner, targets := range aliases {
			if _, found := reachable[owner]; !found {
				continue
			}
			for _, target := range targets {
				if _, found := reachable[target]; !found {
					reachable[target] = struct{}{}
					changed = true
				}
			}
		}
	}
	for owner := range aliases {
		if _, found := reachable[owner]; !found {
			return nil, errors.New("networkjail: dns cname owner invalid")
		}
	}
	answers := make([]netip.Addr, 0, len(addresses))
	for _, answer := range addresses {
		if _, found := reachable[answer.owner]; !found {
			return nil, errors.New("networkjail: dns answer owner invalid")
		}
		answers = append(answers, answer.address)
	}
	return answers, nil
}

func normalizedDNSName(name dnsmessage.Name) (string, error) {
	value := name.String()
	if !strings.HasSuffix(value, ".") {
		return "", errors.New("networkjail: dns name invalid")
	}
	value = strings.TrimSuffix(value, ".")
	normalized, err := normalizeName(value)
	if err != nil {
		return "", errors.New("networkjail: dns name invalid")
	}
	return normalized, nil
}

func dnsWireLengthExact(raw []byte, maxRecords int) bool {
	if len(raw) < 12 {
		return false
	}
	questions := int(binary.BigEndian.Uint16(raw[4:6]))
	answers := int(binary.BigEndian.Uint16(raw[6:8]))
	authorities := int(binary.BigEndian.Uint16(raw[8:10]))
	additionals := int(binary.BigEndian.Uint16(raw[10:12]))
	if questions != 1 || answers < 0 || authorities < 0 || additionals < 0 ||
		answers+authorities+additionals > maxRecords {
		return false
	}
	offset := 12
	var ok bool
	if offset, ok = skipDNSName(raw, offset); !ok || offset+4 > len(raw) {
		return false
	}
	offset += 4
	for count := answers + authorities + additionals; count > 0; count-- {
		if offset, ok = skipDNSName(raw, offset); !ok || offset+10 > len(raw) {
			return false
		}
		length := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10
		if length < 0 || offset+length > len(raw) {
			return false
		}
		offset += length
	}
	return offset == len(raw)
}

func skipDNSName(raw []byte, offset int) (int, bool) {
	start := offset
	for {
		if offset >= len(raw) {
			return 0, false
		}
		length := int(raw[offset])
		switch length & 0xc0 {
		case 0:
			offset++
			if length == 0 {
				return offset, true
			}
			if length > 63 || offset+length > len(raw) {
				return 0, false
			}
			offset += length
		case 0xc0:
			if offset+2 > len(raw) {
				return 0, false
			}
			target := int(binary.BigEndian.Uint16(raw[offset:offset+2]) & 0x3fff)
			if target < 12 || target >= start {
				return 0, false
			}
			return offset + 2, true
		default:
			return 0, false
		}
	}
}

var _ Resolver = (*DoHResolver)(nil)
