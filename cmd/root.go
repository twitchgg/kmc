package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	ccmd "anyun.bitbucket.com/commons/pkg/cmd"
	"anyun.bitbucket.com/commons/pkg/registry"
	"anyun.bitbucket.com/commons/pkg/rpc"
	"anyun.bitbucket.com/commons/pkg/storage"
	"anyun.bitbucket.com/kmc/internal/kmc"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var kmcEnvs struct {
	rpcCertPath string
	rpcBindAddr string

	kmcPath  string
	kmcReset bool
}

var rootCmd = &cobra.Command{
	Use:   "kmc",
	Short: "TSA KMC",
	Run: func(cmd *cobra.Command, args []string) {
		ccmd.InitGlobalVars(true)
		if err := ccmd.ValidateStringVar(&kmcEnvs.rpcCertPath, "rpc_cert_path", true); err != nil {
			logrus.WithField("prefix", "kmc").Fatalf("validate var failed: %s", err.Error())
		}
		if err := ccmd.ValidateStringVar(&kmcEnvs.kmcPath, "kmc_path", true); err != nil {
			logrus.WithField("prefix", "kmc").Fatalf("validate var failed: %s", err.Error())
		}
		ccmd.ValidateStringVar(&ccmd.ServerEnvs.BindEth, "bind_eth", false)
		if err := ccmd.ValidateStringVar(&kmcEnvs.rpcBindAddr, "rpc_bind", true); err != nil {
			logrus.WithField("prefix", "kmc").Fatalf("validate var failed: %s", err.Error())
		}
		ccmd.SetEnvBoolV(&kmcEnvs.kmcReset, "kmc_reset")
		certRoot, err := filepath.Abs(kmcEnvs.rpcCertPath)
		if err != nil {
			logrus.WithField("prefix", "kmc").
				Fatalf("lookup certificate root path failed: %s", err.Error())
		}
		ccmd.ServerEnvs.TrustedPath = certRoot + "/kmc_trusted.crt"
		ccmd.ServerEnvs.CertPath = certRoot + "/kmc_server.crt"
		ccmd.ServerEnvs.PrivkeyPath = certRoot + "/kmc_server.key"
		ccmd.InitBindAddr()
		if err := ccmd.InitEtcd(
			ccmd.GlobalEnvs.EtcdAddr, "/run/kmc-server", initKMC); err != nil {
			logrus.WithField("prefix", "kmc").
				Fatalf("init etcd registry failed: %s", err.Error())
		}
		ccmd.RunWithSysSignal(nil)
	},
}

func initKMC(r *registry.Registry) *registry.NodeStatusEntry {
	nse := &registry.NodeStatusEntry{
		NodeType:   "kmc-server",
		DataCenter: ccmd.GlobalEnvs.DataCenter,
		BindAddr:   ccmd.ServerEnvs.BindAddrSplit,
	}
	serviceEntries := make([]registry.NodeService, 0)
	var trusted, cert, privkey []byte
	var s *kmc.Server
	var err error
	if trusted, err = ioutil.ReadFile(ccmd.ServerEnvs.TrustedPath); err != nil {
		logrus.WithField("prefix", "kmc").
			Fatalf("read kmc server trusted certificate failed: %s", err.Error())
	}
	if cert, err = ioutil.ReadFile(ccmd.ServerEnvs.CertPath); err != nil {
		logrus.WithField("prefix", "kmc").
			Fatalf("read kmc server certificate failed: %s", err.Error())
	}
	if privkey, err = ioutil.ReadFile(ccmd.ServerEnvs.PrivkeyPath); err != nil {
		logrus.WithField("prefix", "kmc").
			Fatalf("read kmc server private key failed: %s", err.Error())
	}
	if s, err = kmc.NewServer(&rpc.ServerConfig{
		TrustedCert:      trusted,
		ServerCert:       cert,
		ServerPrivKey:    privkey,
		RequireAndVerify: true,
		BindAddr:         kmcEnvs.rpcBindAddr,
	}, &storage.KMCStorageConfig{
		Path:  kmcEnvs.kmcPath,
		Reset: kmcEnvs.kmcReset,
	}); err != nil {
		logrus.WithField("prefix", "kmc").
			Fatalf("create kmc server failed: %s", err.Error())
	}
	errChan := s.Start()
	go func() {
		select {
		case err := <-errChan:
			logrus.WithField("prefix", "kmc").
				Fatalf("start kmc server failed: %s", err.Error())
		}
	}()

	port := strings.Split(kmcEnvs.rpcBindAddr, ":")[1]
	for _, ip := range ccmd.ServerEnvs.BindAddr {
		serviceEntries = append(serviceEntries, registry.NodeService{
			Name: "kmc-server", Listener: "tcp+tls+auth://" + ip + ":" + port,
		})
	}

	nse.Services = serviceEntries

	return nse
}

func init() {
	cobra.OnInitialize(func() {})
	viper.AutomaticEnv()
	viper.SetEnvPrefix("TSA")
	rootCmd.Flags().StringVar(&ccmd.GlobalEnvs.LoggerLevel,
		"logger-level", "DEBUG", "logger level")
	rootCmd.Flags().StringVar(&ccmd.GlobalEnvs.EtcdAddr,
		"etcd-endpoints", "", "etcd endpoints")
	rootCmd.Flags().StringVar(&ccmd.GlobalEnvs.DataCenter,
		"data-center", "", "data center name")
	rootCmd.Flags().StringVar(&kmcEnvs.rpcCertPath,
		"rpc-cert-path", "", "KMC gRPC server certificates path")
	rootCmd.Flags().StringVar(&kmcEnvs.rpcBindAddr,
		"rpc-bind", "", "KMC gRPC server bind address")
	rootCmd.Flags().StringVar(&ccmd.ServerEnvs.BindEth, "bind-eth", "",
		"server bind ethernet interface name prefix")
	rootCmd.Flags().StringVar(&kmcEnvs.kmcPath, "kmc-path", "",
		"KMC storage database path")
	rootCmd.Flags().BoolVar(&kmcEnvs.kmcReset, "kmc-reset", false,
		"KMC storage database reset")
}

// Execute TSA KMC main
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
