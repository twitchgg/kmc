package test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"anyun.bitbucket.com/commons/pkg/rpc"
	"anyun.bitbucket.com/ntsc-lab-rpcpb/pkg/center"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/emptypb"
)

func tc(t *testing.T) center.KMCServiceClient {
	certPath, err := filepath.Abs("../../tsa/data/certs/")
	if err != nil {
		t.Fatal(err)
	}
	caPath := certPath + "/kmc_trusted.crt"
	serverCertPath := certPath + "/kmc_client.crt"
	privKeyPath := certPath + "/kmc_client.key"
	trusted, err := ioutil.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ioutil.ReadFile(serverCertPath)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, err := rpc.NewClientTLSConfig(&rpc.ClientTLSConfig{
		CACert:     trusted,
		Cert:       cert,
		PrivKey:    privKey,
		ServerName: "kmc.ntsc.ac.cn",
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := rpc.DialRPCConn(&rpc.DialOptions{
		RemoteAddr: "tcp://127.0.0.1:1357",
		TLSConfig:  tlsConf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return center.NewKMCServiceClient(conn)
}

func TestKMCGenerateRSAKey(t *testing.T) {
	c := tc(t)
	reply, err := c.GenerateRSAKeyPair(context.Background(), &center.RSAKeyPairRequest{
		Bits: center.RSAKeyPairRequest_B2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(reply.PrivateKey.Pem))
	fmt.Println()
	fmt.Println(string(reply.PublicKey.Pem))
}

func TestKMCGenerateECDSAKey(t *testing.T) {
	c := tc(t)
	reply, err := c.GenerateECDSAKeyPair(context.Background(), &center.ECDSAKeyPairRequest{
		EllipticType: center.ECDSAKeyPairRequest_P521,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(reply.PrivateKey.Pem))
	fmt.Println()
	fmt.Println(string(reply.PublicKey.Pem))
}

func TestKMCGenerateWGPrivKey(t *testing.T) {
	c := tc(t)
	reply, err := c.GenerateWireGuardKeyPair(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(reply.PrivateKey.Pem))
	fmt.Println()
	fmt.Println(string(reply.PublicKey.Pem))
}

func TestKMCGenerateWGPreshardKey(t *testing.T) {
	c := tc(t)
	reply, err := c.GenerateWireGuardPresharedKey(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(reply.Pem))
}

var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
	Timeout:             time.Second,      // wait 1 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

func TestKMCCreateCA(t *testing.T) {
	c := tc(t)
	reply, err := c.GenerateCertificateRequest(context.Background(), &center.CSRRequest{
		PkixName: &center.PKIXName{
			Country: "CN",
			// Province:     "Beijing",
			Province: "Shanxi",
			// Locality:     "Beijing",
			Locality: "Xian",
			// Organization: "Cyberspace Administration of China",
			Organization: "National Time Service Center,Chinese Academy of Sciences",
			// CommonName:   "Cyberspace Administration of China Root CA",
			CommonName: "Cheng du cdleadus common view data service client",
		},
		FriendlyName: "中科院国家授时中心根CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GenerateCertificate(context.Background(), &center.CertRequest{
		Cmcsr: reply.Cmcsr,
		IsCA:  true,
		Days:  365 * 5,
		KeyUsage: []center.KeyUsage{
			center.KeyUsage_KeyUsageDigitalSignature,
			center.KeyUsage_KeyUsageCertSign,
			center.KeyUsage_KeyUsageCRLSign,
			center.KeyUsage_KeyUsageContentCommitment,
		},
		ExtUsage: []center.CertificateExtUsage{
			// center.CertificateExtUsage_ExtKeyUsageServerAuth,
			// center.CertificateExtUsage_ExtKeyUsageTimeStamping,
		},
		// PathLength: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestKMCCreateCert(t *testing.T) {
	c := tc(t)
	r1, err := c.GenerateCertificateRequest(context.Background(), &center.CSRRequest{
		PkixName: &center.PKIXName{
			Country:            "CN",
			Province:           "Shanxi",
			Locality:           "Xian",
			Organization:       "NTSC",
			OrganizationalUnit: "NTSC",
			CommonName:         "dev1 main clock device certificate",
			// CommonName:         "TA Dev service sub root certificate",
		},
		DnsNames: []string{
			// "10.10.10.210",
			// "s1.snmp.ntsc.ac.cn",
			// "kmc.ntsc.ac.cn",
			// "s1.cv.ntsc.ac.cn",
			// "ntsc.ac.cn",
			// "dev1.restry.ta.ntsc.ac.cn",
		},
		FriendlyName: "TA开发用主站主钟证书1",
		// FriendlyName: "成都同相科技有限公司",
		Extensions: []*center.X509Extension{
			{
				Id:    []int32{1, 1, 1, 1, 1, 1},
				Value: []byte("628585523e9f9cea5eeaba0b6088d6cf"),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GenerateCertificate(context.Background(), &center.CertRequest{
		Cmcsr: r1.Cmcsr,
		Scmc:  "00000002",
		IsCA:  false,
		Days:  365 * 5,
		KeyUsage: []center.KeyUsage{
			center.KeyUsage_KeyUsageDigitalSignature,
			center.KeyUsage_KeyUsageCertSign,
			// center.KeyUsage_KeyUsageCRLSign,
			center.KeyUsage_KeyUsageContentCommitment,
		},
		ExtUsage: []center.CertificateExtUsage{
			center.CertificateExtUsage_ExtKeyUsageClientAuth,
			// center.CertificateExtUsage_ExtKeyUsageServerAuth,
			// center.CertificateExtUsage_ExtKeyUsageTimeStamping,
		},
		// PathLength: 0,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKMCReset(t *testing.T) {
	s := tc(t)
	if _, err := s.ReflushDB(context.Background(), &empty.Empty{}); err != nil {
		t.Fatal(err)
	}
}

func TestKMCTrustedChain(t *testing.T) {
	s := tc(t)
	reply, err := s.GetTrustedChainBundle(context.Background(),
		&center.IDRequest{
			Id: "00000008",
		})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(reply.Data))
}

func TestKMCRevoke(t *testing.T) {
	s := tc(t)
	if _, err := s.RevokeCert(context.Background(),
		&center.RevokeCertRequest{
			Rcmc: "00000001",
			CertList: []*center.CertRevokeEntity{
				{
					Cmc:    "00000015",
					Reason: center.CertRevokeReason_certificateHold,
					Extensions: []*center.X509Extension{
						{
							Critical: true,
							Value:    []byte("test extension value"),
							Id:       []int32{1, 2, 3, 4, 1},
						},
					},
					Desc: "吊销测试",
				},
			},
		}); err != nil {
		t.Fatal(err)
	}
}

func TestKMCRevokeInfo(t *testing.T) {
	s := tc(t)
	reply, err := s.GetCertRevokeInfo(context.Background(),
		&center.IDRequest{Id: "5a84d5320c70c666efec6bf69e11f9ed629a2a3b"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Cmc != "" {
		fmt.Println(reply.Cmc, reply.Desc, reply.Reason)
	}
}

func TestKMCCreateCRL(t *testing.T) {
	c := tc(t)
	reply, err := c.CreateCRL(context.Background(), &center.CRLCreateRequest{
		Scmc: "00000001",
		Days: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(reply.Data))
}

func TestKMCVerifyTSR(t *testing.T) {
	tsq, _ := ioutil.ReadFile("./data/file1.tsq")
	tsr, _ := ioutil.ReadFile("./data/file1.tsr")
	c := tc(t)
	reply, err := c.VerifyTSR(context.Background(), &center.TSRVerifyRequest{
		Tsq: tsq,
		Tsr: tsr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != 0x00 {
		t.Fatalf("%d %s", reply.Code, reply.Message)
	} else {
		fmt.Println(reply.Message)
	}
}

func TestReadCert(t *testing.T) {
	path := "/mnt/c/Users/twitc/Desktop/cert_ca.crt"
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pemToX509Certificate(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cert.Extensions {

		fmt.Println(e.Id, e.Value)
	}
}
func TestReadCsr(t *testing.T) {
	path := "/mnt/c/Users/twitc/Desktop/cert.csr"
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pemToX509CertificateCSR(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cert.Extensions {
		fmt.Println(e.Id, e.Value)
	}
}

func pemToX509Certificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParseCertificate(block.Bytes)
}

func pemToX509CertificateCSR(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
