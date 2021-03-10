package kmc

import (
	"context"
	"fmt"

	"anyun.bitbucket.com/commons/pkg/rpc"
	"anyun.bitbucket.com/commons/pkg/storage"
	"anyun.bitbucket.com/ntsc-lab-rpcpb/pkg/center"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Server TSA KMC gRPC server
type Server struct {
	rpcConf   *rpc.ServerConfig
	rpcServer *rpc.Server
	ks        *storage.KMCStorage
}

// NewServer create TSA KMC gRPC server
func NewServer(conf *rpc.ServerConfig, storageConf *storage.KMCStorageConfig) (*Server, error) {
	var server Server
	rpcServ, err := rpc.NewServer(conf, []grpc.ServerOption{
		grpc.StreamInterceptor(
			rpc.StreamServerInterceptor(server.certCheckFunc)),
		grpc.UnaryInterceptor(
			rpc.UnaryServerInterceptor(server.certCheckFunc)),
	}, func(g *grpc.Server) {
		center.RegisterKMCServiceServer(g, &server)
	})
	if err != nil {
		return nil, fmt.Errorf("create TSA KMC gRPC server failed: %s", err.Error())
	}
	server.rpcServer = rpcServ
	ks, err := storage.NewKMCStorage(storageConf)
	if err != nil {
		return nil, err
	}
	server.ks = ks
	return &server, nil
}

// Start start TSA KMC gRPC server
func (s *Server) Start() chan error {
	return s.rpcServer.Start()
}

func (s *Server) certCheckFunc(ctx context.Context) (context.Context, error) {
	pr, _ := peer.FromContext(ctx)
	fmt.Println(pr.Addr.String())
	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		if len(info.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "no certificate")
		}
		cert := info.State.PeerCertificates[0]
		logrus.WithField("prefix", "kmc.rpc").Debugf("client common name [%s],issuer common name[%s]",
			cert.Subject.CommonName, cert.Issuer.CommonName)
	default:
		return nil, status.Error(codes.Unauthenticated, "Unknown AuthInfo type")
	}
	return ctx, nil
}

// ReflushDB refluse kmc database
func (s *Server) ReflushDB(context.Context, *empty.Empty) (*empty.Empty, error) {
	if err := s.ks.Reset(); err != nil {
		return nil, rpc.GenerateError(codes.Internal, err)
	}
	return &emptypb.Empty{}, nil
}
