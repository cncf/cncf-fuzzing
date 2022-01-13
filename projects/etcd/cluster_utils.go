package integration

import (
	"fmt"
	"net"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/zap"

	"go.etcd.io/etcd/client/pkg/v3/testutil"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	"go.etcd.io/etcd/client/pkg/v3/types"
)

func NewClusterV3Fuzz(t testutil.TB, cfg *ClusterConfig, f *fuzz.ConsumeFuzzer) (*ClusterV3, error) {
	cfg.UseGRPC = true
	clu, err := NewClusterFromConfigFuzz(t, cfg, f)
	if err != nil {
		return nil, err
	}

	clus := &ClusterV3{
		Cluster: clu,
	}
	clus.Launch(t)

	if !cfg.SkipCreatingClient {
		for _, m := range clus.Members {
			client, err := NewClientV3(m)
			if err != nil {
				return nil, err
			}
			clus.Clients = append(clus.Clients, client)
		}
	}

	return clus, nil
}

func NewClusterFromConfigFuzz(t testutil.TB, cfg *ClusterConfig, f *fuzz.ConsumeFuzzer) (*Cluster, error) {
	c := &Cluster{Cfg: cfg}
	ms := make([]*Member, cfg.Size)
	for i := 0; i < cfg.Size; i++ {
		mem, err := mustNewMemberFuzz(c, t, int64(i), f)
		if err != nil {
			return nil, err
		}
		ms[i] = mem
	}
	c.Members = ms
	if err := fillClusterForMembersFuzz(c); err != nil {
		return nil, err
	}

	return c, nil
}

func mustNewMemberFuzz(c *Cluster, t testutil.TB, memberNumber int64, f *fuzz.ConsumeFuzzer) (*Member, error) {
	m := MustNewMember(t,
		MemberConfig{
			Name:                        generateMemberName(c),
			MemberNumber:                memberNumber,
			AuthToken:                   c.Cfg.AuthToken,
			PeerTLS:                     c.Cfg.PeerTLS,
			ClientTLS:                   c.Cfg.ClientTLS,
			QuotaBackendBytes:           c.Cfg.QuotaBackendBytes,
			MaxTxnOps:                   c.Cfg.MaxTxnOps,
			MaxRequestBytes:             c.Cfg.MaxRequestBytes,
			SnapshotCount:               c.Cfg.SnapshotCount,
			SnapshotCatchUpEntries:      c.Cfg.SnapshotCatchUpEntries,
			GrpcKeepAliveMinTime:        c.Cfg.GRPCKeepAliveMinTime,
			GrpcKeepAliveInterval:       c.Cfg.GRPCKeepAliveInterval,
			GrpcKeepAliveTimeout:        c.Cfg.GRPCKeepAliveTimeout,
			ClientMaxCallSendMsgSize:    c.Cfg.ClientMaxCallSendMsgSize,
			ClientMaxCallRecvMsgSize:    c.Cfg.ClientMaxCallRecvMsgSize,
			UseIP:                       c.Cfg.UseIP,
			UseBridge:                   c.Cfg.UseBridge,
			UseTCP:                      c.Cfg.UseTCP,
			EnableLeaseCheckpoint:       c.Cfg.EnableLeaseCheckpoint,
			LeaseCheckpointInterval:     c.Cfg.LeaseCheckpointInterval,
			WatchProgressNotifyInterval: c.Cfg.WatchProgressNotifyInterval,
		})
	m.DiscoveryURL = c.Cfg.DiscoveryURL
	if c.Cfg.UseGRPC {
		if err := listenGRPCFuzz(m, f); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func generateMemberName(c *Cluster) string {
	c.LastMemberNum++
	return fmt.Sprintf("m%v", c.LastMemberNum-1)
}

func listenGRPCFuzz(m *Member, f *fuzz.ConsumeFuzzer) error {
	// prefix with localhost so cert has right domain
	network, host, port := grpcAddrFuzz(m)
	port, err := f.GetStringFrom("abcdefghijklmnopqrstuvwxyz0123456789", 4)
	if err != nil {
		return err
	}
	grpcAddr := host + ":" + port
	m.Logger.Info("LISTEN GRPC", zap.String("grpcAddr", grpcAddr), zap.String("m.Name", m.Name))
	grpcListener, err := net.Listen(network, grpcAddr)
	if err != nil {
		return fmt.Errorf("listen failed on grpc socket %s (%v)", grpcAddr, err)
	}
	m.GrpcURL = fmt.Sprintf("%s://%s", clientScheme(m), grpcAddr)
	if m.UseBridge {
		_, err = addBridge(m)
		if err != nil {
			grpcListener.Close()
			return err
		}
	}
	m.GrpcListener = grpcListener
	return nil
}

func clientScheme(m *Member) string {
	switch {
	case m.UseTCP && m.ClientTLSInfo != nil:
		return "https"
	case m.UseTCP && m.ClientTLSInfo == nil:
		return "http"
	case !m.UseTCP && m.ClientTLSInfo != nil:
		return "unixs"
	case !m.UseTCP && m.ClientTLSInfo == nil:
		return "unix"
	}
	m.Logger.Panic("Failed to determine client schema")
	return ""
}

func grpcAddrFuzz(m *Member) (network, host, port string) {
	// prefix with localhost so cert has right domain
	host = "localhost"
	if m.UseIP { // for IP-only TLS certs
		host = "127.0.0.1"
	}
	network = "unix"
	if m.UseTCP {
		network = "tcp"
	}
	port = m.Name
	if m.UseTCP {
		port = fmt.Sprintf("%d", GrpcPortNumber(m.UniqNumber, m.MemberNumber))
	}
	return network, host, port
}

func fillClusterForMembersFuzz(c *Cluster) error {
	if c.Cfg.DiscoveryURL != "" {
		// Cluster will be discovered
		return nil
	}

	addrs := make([]string, 0)
	for _, m := range c.Members {
		scheme := SchemeFromTLSInfoFuzz(m.PeerTLSInfo)
		for _, l := range m.PeerListeners {
			addrs = append(addrs, fmt.Sprintf("%s=%s://%s", m.Name, scheme, l.Addr().String()))
		}
	}
	clusterStr := strings.Join(addrs, ",")
	var err error
	for _, m := range c.Members {
		m.InitialPeerURLsMap, err = types.NewURLsMap(clusterStr)
		if err != nil {
			return err
		}
	}
	return nil
}

func SchemeFromTLSInfoFuzz(tls *transport.TLSInfo) string {
	if tls == nil {
		return URLScheme
	}
	return URLSchemeTLS
}

func addBridge(m *Member) (*bridge, error) {
	network, host, port := grpcAddrFuzz(m)
	grpcAddr := host + ":" + port
	bridgeAddr := grpcAddr + "0"
	m.Logger.Info("LISTEN BRIDGE", zap.String("grpc-address", bridgeAddr), zap.String("member", m.Name))
	bridgeListener, err := transport.NewUnixListener(bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("listen failed on bridge socket %s (%v)", bridgeAddr, err)
	}
	m.GrpcBridge, err = newBridge(dialer{network: network, addr: grpcAddr}, bridgeListener)
	if err != nil {
		bridgeListener.Close()
		return nil, err
	}
	m.GrpcURL = clientScheme(m) + "://" + bridgeAddr
	return m.GrpcBridge, nil
}
