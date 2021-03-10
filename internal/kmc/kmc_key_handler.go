package kmc

import (
	"context"
	"crypto/elliptic"
	"fmt"

	"anyun.bitbucket.com/commons/pkg/rpc"
	auth "anyun.bitbucket.com/commons/pkg/secure"
	"anyun.bitbucket.com/commons/pkg/storage"
	"anyun.bitbucket.com/ntsc-lab-rpcpb/pkg/center"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GenerateRSAKeyPair generate RSA key pair
func (s *Server) GenerateRSAKeyPair(ctx context.Context,
	req *center.RSAKeyPairRequest) (*center.KeyPairReply, error) {
	bits := 0
	switch req.Bits {
	case center.RSAKeyPairRequest_B4096:
		bits = 4096
	case center.RSAKeyPairRequest_B2048:
		bits = 2048
	case center.RSAKeyPairRequest_B1024:
		bits = 1024
	case center.RSAKeyPairRequest_B512:
		bits = 512
	default:
		return nil, status.Error(codes.InvalidArgument,
			fmt.Sprintf("un supported bits: %v", req.Bits))
	}
	privKey, pubKey, err := auth.GenerateRSAKeyPair(bits)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("generate RSA key pair failed: %s", err.Error()))
	}
	privKeyPEM, err := auth.RSAPrivKeyToPEM(privKey)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert RSA private key to PEM format failed: %s", err.Error()))
	}
	privKeySerial, err := s.ks.PutPrivateKey(&storage.PrivateKeyEntity{
		Data:    privKeyPEM,
		KeyType: &storage.KeyTypeEntity{ID: 1},
		Alg:     req.Bits.String(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("storage RSA private key to PEM format failed: %s", err.Error()))
	}
	pubKeyPEM, err := auth.RSAPubKeyToPEM(pubKey)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert RSA public key to PEM format failed: %s", err.Error()))
	}
	return &center.KeyPairReply{
		PrivateKey: &center.KeyReply{Pem: privKeyPEM, Cmk: privKeySerial},
		PublicKey:  &center.KeyReply{Pem: pubKeyPEM},
	}, nil
}

// GenerateECDSAKeyPair generate ECDSA key pair
func (s *Server) GenerateECDSAKeyPair(ctx context.Context,
	req *center.ECDSAKeyPairRequest) (*center.KeyPairReply, error) {
	var curve elliptic.Curve
	switch req.EllipticType {
	case center.ECDSAKeyPairRequest_P521:
		curve = elliptic.P521()
	case center.ECDSAKeyPairRequest_P384:
		curve = elliptic.P384()
	case center.ECDSAKeyPairRequest_P256:
		curve = elliptic.P256()
	case center.ECDSAKeyPairRequest_P224:
		curve = elliptic.P224()
	default:
		return nil, status.Error(codes.InvalidArgument,
			fmt.Sprintf("unsupport bits: %v", req.EllipticType))
	}
	privKey, pubKey, err := auth.GenerateECDSAKeyPair(curve)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("generate ECDSA key pair failed: %s", err.Error()))
	}
	privKeyPEM, err := auth.ECDSAPrivKeyToPEM(privKey)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert ECDSA private key to PEM format failed: %s", err.Error()))
	}
	pubKeyPEM, err := auth.ECDSAPubKeyToPEM(pubKey)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert ECDSA public key to PEM format failed: %s", err.Error()))
	}
	privKeySerial, err := s.ks.PutPrivateKey(&storage.PrivateKeyEntity{
		Data:    privKeyPEM,
		KeyType: &storage.KeyTypeEntity{ID: 2},
		Alg:     req.EllipticType.String(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("storage ECDSA private key to PEM format failed: %s", err.Error()))
	}
	return &center.KeyPairReply{
		PrivateKey: &center.KeyReply{Pem: privKeyPEM, Cmk: privKeySerial},
		PublicKey:  &center.KeyReply{Pem: pubKeyPEM},
	}, nil
}

// GenerateWireGuardKeyPair generate WireGuard key pair
func (s *Server) GenerateWireGuardKeyPair(ctx context.Context,
	req *empty.Empty) (*center.KeyPairReply, error) {
	privKey, pubKey, err := auth.GenerateWireguardKeyPair()
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("generate wireguard key pair failed: %s", err.Error()))
	}
	privKeyPEM, err := auth.WireguardPrivKeyToPEM(privKey)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert wireguard private key to PEM format failed: %s", err.Error()))
	}
	pubKeyPEM, err := auth.WireguardPubKeyToPEM(pubKey)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert wireguard public key to PEM format failed: %s", err.Error()))
	}
	privKeySerial, err := s.ks.PutPrivateKey(&storage.PrivateKeyEntity{
		Data:    privKeyPEM,
		KeyType: &storage.KeyTypeEntity{ID: 3},
		Alg:     "CURVE25519 ",
	})
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("storage wireguard private key to PEM format failed: %s", err.Error()))
	}
	return &center.KeyPairReply{
		PrivateKey: &center.KeyReply{Pem: privKeyPEM, Cmk: privKeySerial},
		PublicKey:  &center.KeyReply{Pem: pubKeyPEM},
	}, nil
}

// GenerateWireGuardPresharedKey generate WireGuard preshared key
func (s *Server) GenerateWireGuardPresharedKey(ctx context.Context,
	req *empty.Empty) (*center.KeyReply, error) {
	psk, err := auth.GenerateWireguardPresharedKey()
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("generate wireguard pre-shadred key failed: %s", err.Error()))
	}
	pskPEM, err := auth.WireguardPreShadedKeyToPEM(psk)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("convert wireguard pre-shared key to PEM format failed: %s", err.Error()))
	}
	pskSerial, err := s.ks.PutPrivateKey(&storage.PrivateKeyEntity{
		Data:    pskPEM,
		KeyType: &storage.KeyTypeEntity{ID: 4},
		Alg:     "CURVE25519",
	})
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("storage wireguard pre-shared key to PEM format failed: %s", err.Error()))
	}
	return &center.KeyReply{Pem: pskPEM, Cmk: pskSerial}, nil
}

// GetPrivateKey get private key
func (s *Server) GetPrivateKey(ctx context.Context,
	req *center.GetPrivateKeyRequest) (*center.KeyReply, error) {
	if req.Cmk == "" {
		return nil, rpc.GenerateArgumentRequiredError("key serial number")
	}
	privkey, err := s.ks.GetPrivateKey(req.Cmk)
	if err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("get private key with serial [%s] failed: %s",
				req.Cmk, err.Error()))
	}
	if privkey == nil {
		return nil, status.Error(codes.NotFound,
			fmt.Sprintf("not found private key with serial [%s]", req.Cmk))
	}
	return &center.KeyReply{
		Cmk: req.Cmk,
		Pem: privkey.Data,
	}, nil
}
