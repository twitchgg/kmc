package kmc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"

	"anyun.bitbucket.com/commons/pkg/rpc"
	auth "anyun.bitbucket.com/commons/pkg/secure"
	"anyun.bitbucket.com/commons/pkg/storage"
	"anyun.bitbucket.com/ntsc-lab-rpcpb/pkg/center"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
)

const (
	defaultRSAPrivKeyBits     = 2048
	defaultRSAPrivKeyBitsName = "B2048"
)

// GenerateCertificateRequest generate certificate request
func (s *Server) GenerateCertificateRequest(ctx context.Context,
	req *center.CSRRequest) (*center.CSRReply, error) {
	var err error
	if req.PkixName == nil {
		return nil, rpc.GenerateArgumentRequiredError("pkixName")
	}

	pkixName := pkix.Name{
		Country:            []string{req.PkixName.Country},
		Province:           []string{req.PkixName.Province},
		Locality:           []string{req.PkixName.Locality},
		Organization:       []string{req.PkixName.Organization},
		OrganizationalUnit: []string{req.PkixName.OrganizationalUnit},
		CommonName:         req.PkixName.CommonName,
	}
	var privKey interface{}
	var privKeyPEM []byte
	if req.PrivkeySerial == "" {
		logrus.WithField("prefix", "kmc.rpc").
			Debugf("private key pem is not set,generate new TSA private key with default bits [%d]",
				defaultRSAPrivKeyBits)
		privKey, _, err = auth.GenerateRSAKeyPair(defaultRSAPrivKeyBits)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("generate rsa key pair failed: %s", err.Error()))
		}
		if privKeyPEM, err = auth.RSAPrivKeyToPEM(privKey.(*rsa.PrivateKey)); err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("RSA private key to PEM format failed: %s", err.Error()))
		}
		if req.PrivkeySerial, err = s.ks.PutPrivateKey(&storage.PrivateKeyEntity{
			KeyType: &storage.KeyTypeEntity{ID: 1},
			Data:    privKeyPEM,
			Alg:     defaultRSAPrivKeyBitsName,
		}); err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("add private key to storage failed: %s", err.Error()))
		}
	}
	privKeyEntity, err := s.ks.GetPrivateKey(req.PrivkeySerial)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("get [%s] private key with serial [%s] failed: %s",
				privKeyEntity.KeyType.Name, req.PrivkeySerial, err.Error()))
	}
	if privKeyEntity == nil {
		return nil, rpc.GenerateError(codes.InvalidArgument,
			fmt.Errorf("not found private key with serial: %s", req.PrivkeySerial))
	}
	privKeyPEM = privKeyEntity.Data
	switch privKeyEntity.KeyType.Name {
	case "RSA":
		privKey, err = auth.PEMToRSAPrivKey(privKeyPEM)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("parse RSA key with PEM format failed: %s", err.Error()))
		}
	case "ECDSA":
		privKey, err = auth.PEMToECDSAPrivKey(privKeyPEM)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("parse ECDSA key with PEM format failed: %s", err.Error()))
		}
	default:
		return nil, rpc.GenerateError(codes.InvalidArgument,
			fmt.Errorf("unsupport key type"))
	}
	if privKey == nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("not found RSA private key with serial [%s]", req.PrivkeySerial))
	}
	logrus.WithField("prefix", "kmc.rpc").
		Debugf("request subject: %s", pkixName.String())
	exs := make([]pkix.Extension, 0)
	if req.Extensions != nil && len(req.Extensions) > 0 {
		for _, e := range req.Extensions {
			exs = append(exs, pkix.Extension{
				Id:       convertObjectIdentifier(e.Id),
				Value:    e.Value,
				Critical: e.Critical,
			})
			logrus.WithField("prefix", "kmc.rpc").
				Debugf("request extension id %v value [%s] ", e.Id, e.Value)
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:            pkixName,
		SignatureAlgorithm: x509.SHA512WithRSA,
		// Extensions:         exs,
		ExtraExtensions: exs,
	}
	if req.DnsNames != nil && len(req.DnsNames) > 0 {
		csrTemplate.DNSNames = req.DnsNames
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("create certificate request failed: %s", err.Error()))
	}
	csrPEM, err := auth.DataToPEM(csr, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("certificate request to PEM format failed: %s", err.Error()))
	}
	csrSerial, err := s.ks.PutX509CertificateRequest(&storage.X509CertificateRequestEntity{
		Data:       csrPEM,
		PrivateKey: privKeyEntity,
		Desc:       req.FriendlyName,
	})
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("add certificate request to storage failed: %s", err.Error()))
	}
	return &center.CSRReply{
		Cmk:   req.PrivkeySerial,
		Cmcsr: csrSerial,
	}, nil
}

// GenerateCertificate generate certificate
func (s *Server) GenerateCertificate(ctx context.Context,
	req *center.CertRequest) (*center.CertReply, error) {
	if req.KeyUsage == nil || len(req.KeyUsage) == 0 {
		return nil, rpc.GenerateArgumentRequiredError("key usage")
	}
	var signPrivKeyEntity *storage.PrivateKeyEntity
	var signPrivkey interface{}
	var signPrivkeyPEM []byte
	var csr *x509.CertificateRequest
	var signCert *x509.Certificate
	var cert *x509.Certificate

	csrEntity, err := s.ks.GetX509CertificateRequest(req.Cmcsr)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("query certificate request with serial [%s] failed: %s",
				req.Cmcsr, err.Error()))
	}
	if csr, err = auth.PEMToX509CertificateRequest(csrEntity.Data); err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("format certificate request with serial [%s] failed: %s",
				req.Cmcsr, err.Error()))
	}
	privkeyID := fmt.Sprintf("%08d", csrEntity.PrivateKey.ID)
	signPrivKeyEntity, err = s.ks.GetPrivateKey(privkeyID)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("query certificate request private key with serial [%s] failed: %s",
				privkeyID, err.Error()))
	}
	signPrivkeyPEM = signPrivKeyEntity.Data
	var signCertIntID int
	if req.Scmc != "" {
		signCertEntity, err := s.ks.GetX509Certificate(req.Scmc)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("query sign certificate with serial [%s] failed: %s",
					req.Scmc, err.Error()))
		} else if signCertEntity == nil {

		}
		signCertIntID = signCertEntity.ID
		if signCert, err = auth.PEMToX509Certificate(signCertEntity.Data); err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("format sign certificate with serial [%s] failed: %s",
					req.Scmc, err.Error()))
		}
		signCsrID := fmt.Sprintf("%08d", signCertEntity.Csr)
		signCsr, err := s.ks.GetX509CertificateRequest(signCsrID)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("query sign certificate request with serial [%s] failed: %s",
					signCsrID, err.Error()))
		}
		privkeyID = fmt.Sprintf("%08d", signCsr.PrivateKey.ID)
		signPrivKeyEntity, err = s.ks.GetPrivateKey(privkeyID)
		if err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("query sign certificate request private key with serial [%s] failed: %s",
					privkeyID, err.Error()))
		}
		signPrivkeyPEM = signPrivKeyEntity.Data
	}
	switch signPrivKeyEntity.KeyType.Name {
	case "RSA":
		if signPrivkey, err = auth.PEMToRSAPrivKey(signPrivkeyPEM); err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("format sign certificate RSA private key failed: %s", err.Error()))
		}
	case "ECDSA":
		if signPrivkey, err = auth.PEMToECDSAPrivKey(signPrivkeyPEM); err != nil {
			return nil, rpc.GenerateError(codes.Internal,
				fmt.Errorf("format sign certificate ECDSA private key failed: %s", err.Error()))
		}
	default:
		return nil, rpc.GenerateArgumentRequiredError("unsupport key type")
	}
	var extUsage []x509.ExtKeyUsage
	var keyUsages x509.KeyUsage
	for _, u := range req.KeyUsage {
		keyUsages = keyUsages | x509.KeyUsage(u)
	}
	if req.ExtUsage != nil && len(req.ExtUsage) > 0 {
		hasTimestampExtUsage := false
		for _, u := range req.ExtUsage {
			if u == center.CertificateExtUsage_ExtKeyUsageTimeStamping {
				hasTimestampExtUsage = true
			}
		}
		if hasTimestampExtUsage {
			if len(req.ExtUsage) > 1 {
				return nil, rpc.GenerateError(codes.InvalidArgument,
					fmt.Errorf("timestamp certificate moust be only one ext usage"))
			}
		}
		for _, u := range req.ExtUsage {
			extUsage = append(extUsage, x509.ExtKeyUsage(u))
		}
	} else {
		extUsage = nil
	}
	serial, err := s.genSerialNumber()
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("generate certificate serial failed: %s", err.Error()))
	}
	if cert, err = auth.GenerateCertificate(
		csr, req.IsCA, req.Days,
		serial, signCert, signPrivkey,
		keyUsages, extUsage, int(req.PathLength),
	); err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("format sign certificate with sign certificate serial [%s] failed: %s",
				req.Scmc, err.Error()))
	}
	certPEM, err := auth.X509CertificateToPEM(cert)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("generate certificate with sign certificate serial [%s] failed: %s",
				req.Scmc, err.Error()))
	}
	entity := &storage.X509CertificateEntity{
		Serial:     fmt.Sprintf("%x", cert.SerialNumber),
		Data:       certPEM,
		IsCA:       req.IsCA,
		Csr:        csrEntity.ID,
		ExpireTime: cert.NotAfter,
	}
	if signCertIntID > 0 {
		entity.Issuer = signCertIntID
	}
	certSerial, err := s.ks.PutX509Certificate(entity)
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal,
			fmt.Errorf("storage certificate failed: %s", err.Error()))
	}
	return &center.CertReply{
		Cmc: certSerial,
	}, nil
}
func convertObjectIdentifier(data []int32) []int {
	id := make([]int, len(data))
	for i, v := range data {
		id[i] = int(v)
	}
	return id
}
func (s *Server) genSerialNumber() (*big.Int, error) {
	serial, err := rand.Int(
		rand.Reader,
		(&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil, err
	}
	if entity, err := s.ks.GetX509CertificateBySerial(serial); err != nil {
		return nil, err
	} else if entity != nil {
		return s.genSerialNumber()
	}
	return serial, nil
}

// GetTrustedChainBundle get certificate trusted chain bundle
func (s *Server) GetTrustedChainBundle(ctx context.Context,
	req *center.IDRequest) (*center.CertReply, error) {
	if req.Id == "" {
		return nil, rpc.GenerateArgumentRequiredError("id")
	}
	var err error
	var bundleCerts []*storage.X509CertificateEntity
	if bundleCerts, err = s.queryParentCert(req.Id,
		[]*storage.X509CertificateEntity{}); err != nil {
		return nil, rpc.GenerateError(codes.Internal, err)
	}
	var buf bytes.Buffer
	for _, bc := range bundleCerts {
		if _, err = buf.Write(bc.Data); err != nil {
			return nil, rpc.GenerateError(codes.Internal, err)
		}
	}
	return &center.CertReply{
		Cmc:  req.Id,
		Data: buf.Bytes(),
	}, nil
}

// GetCertificate get certificate
func (s *Server) GetCertificate(ctx context.Context,
	req *center.CertQueryRequest) (*center.CertReply, error) {
	var entity *storage.X509CertificateEntity
	var err error
	if req.Cmc != "" {
		entity, err = s.ks.GetX509Certificate(req.Cmc)
	} else if req.Serial != "" {
		entity, err = s.ks.GetX509CertificateBySerialHex(req.Serial)
	}
	if err != nil {
		return nil, rpc.GenerateError(codes.Internal, err)
	}
	if entity == nil {
		return nil, rpc.GenerateError(codes.NotFound, fmt.Errorf("not found certificate"))
	}
	return &center.CertReply{
		Cmc:  fmt.Sprintf("%08d", entity.ID),
		Data: entity.Data,
	}, nil
}

func (s *Server) queryParentCert(id string,
	bcs []*storage.X509CertificateEntity) ([]*storage.X509CertificateEntity, error) {
	cert, err := s.ks.GetX509Certificate(id)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("not found certificate with serial [%s]", id)
	}
	if cert.IsCA {
		bcs = append(bcs, cert)
	}
	if cert.Issuer == 0 {
		return bcs, nil
	}
	pid := fmt.Sprintf("%08d", cert.Issuer)
	return s.queryParentCert(pid, bcs)
}
