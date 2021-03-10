package kmc

import (
	"context"
	"fmt"

	"anyun.bitbucket.com/commons/pkg/rpc"
	auth "anyun.bitbucket.com/commons/pkg/secure"
	pb "anyun.bitbucket.com/ntsc-lab-rpcpb/pkg/center"
	ts "anyun.bitbucket.com/timestamp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
)

// VerifyTSR verify timestamp reply
func (s *Server) VerifyTSR(ctx context.Context,
	req *pb.TSRVerifyRequest) (*pb.TSRVerifyReply, error) {
	if req.Tsq == nil || len(req.Tsq) == 0 {
		return nil, rpc.GenerateArgumentRequiredError("tsq")
	}
	tsq, err := ts.ParseRequest(req.Tsq)
	if err != nil {
		return nil, rpc.GenerateArgumentError(
			fmt.Sprintf("parse TSA timestamp request failed: %s", err.Error()))
	}
	hashedMsg := fmt.Sprintf("%x", tsq.HashedMessage)
	if req.Tsr == nil || len(req.Tsr) == 0 {
		return nil, rpc.GenerateArgumentRequiredError("tsr")
	}
	tsr, err := ts.ParseResponse(req.Tsr)
	if err != nil {
		return nil, rpc.GenerateArgumentError(
			fmt.Sprintf("parse timestamp reply failed: %s", err.Error()))
	}
	tsrHashMsg := fmt.Sprintf("%x", tsr.HashedMessage)
	if hashedMsg != tsrHashMsg {
		return &pb.TSRVerifyReply{
			Code:    0x01,
			Message: "file hash not match",
		}, nil
	}
	if len(tsr.P7.Signers) != 1 {
		return &pb.TSRVerifyReply{
			Code:    0x02,
			Message: fmt.Sprintf("TSA PKCS7 signers length [%d]", len(tsr.P7.Signers)),
		}, nil
	}
	signerInfo := tsr.P7.Signers[0]
	signCertSerial := fmt.Sprintf("%x", signerInfo.IssuerAndSerialNumber.SerialNumber)
	logrus.WithField("prefix", "tsa.verify").
		Debugf("verify sign certificate serial: %s", signCertSerial)
	signCertRevokeReply, err := s.GetCertRevokeInfo(context.Background(),
		&pb.IDRequest{Id: signCertSerial})
	if err != nil {
		return &pb.TSRVerifyReply{
			Code: 0x03,
			Message: fmt.Sprintf("verify certificate [%s] revoke info failed: %s",
				signCertSerial, err.Error()),
		}, nil
	}

	if signCertRevokeReply.Cmc != "" {
		return &pb.TSRVerifyReply{
			Code: 0x04,
			Message: fmt.Sprintf("sign certificate [%s] revoked",
				signCertSerial),
		}, nil
	}

	certReply, err := s.GetCertificate(context.Background(),
		&pb.CertQueryRequest{
			Serial: signCertSerial,
		})
	if err != nil {
		return &pb.TSRVerifyReply{
			Code: 0x05,
			Message: fmt.Sprintf("query sign certificate failed: %s",
				status.Convert(err).Message()),
		}, nil
	}
	trustedChainReply, err := s.GetTrustedChainBundle(context.Background(),
		&pb.IDRequest{
			Id: certReply.Cmc,
		})
	if err != nil {
		return &pb.TSRVerifyReply{
			Code: 0x06,
			Message: fmt.Sprintf("quert certificate [%s] trusted chain failed: %s",
				signCertSerial, status.Convert(err).Message()),
		}, nil
	}
	if trustedChainReply.Data == nil {
		return &pb.TSRVerifyReply{
			Code:    0x07,
			Message: fmt.Sprintf("no certificate [%s] trusted chain", signCertSerial),
		}, nil
	}
	trustedCerts, err := auth.ConvertTLSCertificates(trustedChainReply.Data)
	if err != nil {
		return &pb.TSRVerifyReply{
			Code: 0x08,
			Message: fmt.Sprintf("convert certificate [%s] trusted chain failed: %s",
				signCertSerial, err.Error()),
		}, nil
	}
	for _, tCert := range trustedCerts {
		tSerial := fmt.Sprintf("%x", tCert.SerialNumber)
		reply, err := s.GetCertRevokeInfo(context.Background(),
			&pb.IDRequest{Id: tSerial})
		if err != nil {
			return &pb.TSRVerifyReply{
				Code: 0x09,
				Message: fmt.Sprintf("verify certificate [%s] revoke info failed: %s",
					tSerial, err.Error()),
			}, nil
		}
		if reply.Cmc != "" {
			return &pb.TSRVerifyReply{
				Code: 0x0a,
				Message: fmt.Sprintf("certificate [%s] revoked",
					tSerial),
			}, nil
		}
	}
	trustedPool, err := auth.DecodeCertificateChainPool(trustedChainReply.Data)
	if err != nil {
		return &pb.TSRVerifyReply{
			Code: 0x0b,
			Message: fmt.Sprintf("convert certificate [%s] trusted chain pool failed: %s",
				signCertSerial, err.Error()),
		}, nil
	}
	var verifyErr error
	if !tsr.AddTSACertificate && tsr.P7.GetOnlySigner() == nil {
		signCert, err := auth.PEMToX509Certificate(certReply.Data)
		if err != nil {
			return &pb.TSRVerifyReply{
				Code:    0x0c,
				Message: fmt.Sprintf("parse TSA sign certificate failed: %s", err.Error()),
			}, nil
		}
		verifyErr = tsr.Verify(signCert, trustedPool)
	} else {
		verifyErr = tsr.Verify(nil, trustedPool)
	}
	if verifyErr != nil {
		return &pb.TSRVerifyReply{
			Code: 0x0d,
			Message: fmt.Sprintf("certificate verify failed: %s",
				verifyErr.Error()),
		}, nil
	}
	return &pb.TSRVerifyReply{
		Code:    0x00,
		Message: "verify ok",
	}, nil
}
