package kmc

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"anyun.bitbucket.com/commons/pkg/rpc"
	auth "anyun.bitbucket.com/commons/pkg/secure"
	"anyun.bitbucket.com/commons/pkg/storage"
	"anyun.bitbucket.com/ntsc-lab-rpcpb/pkg/center"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	oidExtensionReasonCode = asn1.ObjectIdentifier{2, 5, 29, 21}
)

// CreateCRL generate CRL
func (s *Server) CreateCRL(ctx context.Context,
	req *center.CRLCreateRequest) (*center.CRLCreateReply, error) {
	if req.Scmc == "" {
		return nil, rpc.GenerateArgumentError("not found CRL issuer certificate id")
	}
	issuerCertEntity, err := s.ks.GetX509Certificate(req.Scmc)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("get issuer certificate [%s]failed: %s", req.Scmc, err.Error()))
	}
	if issuerCertEntity == nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("not found issuer certificate [%s]", req.Scmc))
	}
	if !issuerCertEntity.IsCA {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("issuer certificate [%s] is not CA,can not generate CRL list", req.Scmc))
	}
	cert, err := auth.PEMToX509Certificate(issuerCertEntity.Data)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("parse x509 certificate failed: %s", err))
	}
	if x509.KeyUsageCRLSign&cert.KeyUsage == 0 {
		return nil, rpc.GenerateArgumentError("certificate key usage not contain [CRL sign]")
	}
	var signer crypto.Signer
	issuerCsr, err := s.ks.GetX509CertificateRequest(fmt.Sprintf("%08d", issuerCertEntity.ID))
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("get issuer certfiicate [%s] request failed: %s",
				req.Scmc, err.Error()))
	}
	switch issuerCsr.PrivateKey.KeyType.Name {
	case "RSA":
		signer, err = auth.PEMToRSAPrivKey(issuerCsr.PrivateKey.Data)
	case "ECDSC":
		signer, err = auth.PEMToECDSAPrivKey(issuerCsr.PrivateKey.Data)
	default:
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("unsupport issuer certfiicate [%s] private key type: %s",
				req.Scmc, issuerCsr.PrivateKey.KeyType.Name))
	}
	var certs storage.CertSlice
	if err := s.ks.GetSubCertificates(req.Scmc, true, &certs); err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("get CA certfiicate [%s] subordinate CA certificates failed: %s",
				req.Scmc, err.Error()))
	}
	if len(certs.Entities) == 0 {
		return nil, rpc.GenerateArgumentError(
			fmt.Sprintf("not found CRL sign certificates with certificate [%s]", req.Scmc))
	}
	entities, err := s.ks.GetRevokedCerts(&certs)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("get issuer certfiicate [%s] revoked certificates failed: %s",
				req.Scmc, err.Error()))
	}
	var crlList []pkix.RevokedCertificate
	for _, r := range entities {
		bs := make([]byte, 2)
		binary.LittleEndian.PutUint16(bs, uint16(r.Reason.ID))
		crlList = append(crlList, pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(int64(r.Cert.ID)),
			RevocationTime: r.CreateTime,
			Extensions: []pkix.Extension{
				{
					Id:       oidExtensionReasonCode,
					Value:    bs,
					Critical: true,
				},
			},
		})
	}

	expriedTime := time.Now().Add(time.Hour * time.Duration(24*req.Days))
	data, err := auth.CreateGenericCRL(crlList, signer, cert, expriedTime)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("create CRL with issuer certfiicate [%s]failed: %s",
				req.Scmc, err.Error()))
	}
	pem, err := auth.DataToPEM(data, "X509 CRL")
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("create CRL PEM with issuer certfiicate [%s]failed: %s",
				req.Scmc, err.Error()))
	}
	return &center.CRLCreateReply{
		Id:   "",
		Data: pem,
	}, nil
}

// RevokeCert revoke certificate
func (s *Server) RevokeCert(ctx context.Context,
	req *center.RevokeCertRequest) (*empty.Empty, error) {
	if req.Rcmc == "" {
		return nil, rpc.GenerateArgumentError("revoke certificate id")
	}

	revokerID, _ := strconv.ParseInt(req.Rcmc, 10, 64)
	if req.CertList == nil || len(req.CertList) == 0 {
		return nil, rpc.GenerateArgumentError("not found revoke certificates")
	}
	var entities []*storage.RevokeEntity
	for _, e := range req.CertList {
		cert, err := s.ks.GetX509Certificate(e.Cmc)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("get certificate [%s] failed: %s", e.Cmc, err.Error()))
		}
		if cert == nil {
			return nil, rpc.GenerateError(codes.InvalidArgument,
				fmt.Errorf("not found certificate [%s]", e.Cmc))
		}
		entities = append(entities, &storage.RevokeEntity{
			Revoker: &storage.X509CertificateEntity{ID: int(revokerID)},
			Cert:    &storage.X509CertificateEntity{Serial: cert.Serial},
			Reason:  &storage.RevokeReasonEntity{ID: int(e.Reason)},
			Desc:    e.Desc,
		})
	}
	if err := s.ks.PutRevokeCert(entities); err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("kmc insert data to db failed: %s", err.Error()))
	}
	return &emptypb.Empty{}, nil
}

// GetCertRevokeInfo get certificate revoke info
func (s *Server) GetCertRevokeInfo(ctx context.Context,
	req *center.IDRequest) (*center.CertRevokeEntity, error) {
	if req.Id == "" {
		return nil, rpc.GenerateArgumentError("not found certificate serial number hex string")
	}
	entity, err := s.ks.GetRevokeCertInfo(req.Id)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal, err)
	}
	if entity == nil {
		return &center.CertRevokeEntity{}, nil
	}
	return &center.CertRevokeEntity{
		Cmc:    fmt.Sprintf("%08d", entity.Cert.ID),
		Desc:   entity.Desc,
		Reason: center.CertRevokeReason(entity.Reason.ID),
	}, nil
}
