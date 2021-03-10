module anyun.bitbucket.com/kmc

go 1.15

require (
	anyun.bitbucket.com/commons v0.0.0
	anyun.bitbucket.com/ntsc-lab-rpcpb v0.0.0
	anyun.bitbucket.com/timestamp v0.0.0
	github.com/golang/protobuf v1.4.3
	github.com/mattn/go-colorable v0.1.7
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.1
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	google.golang.org/grpc v1.27.0
	google.golang.org/protobuf v1.25.0
)

replace (
	anyun.bitbucket.com/commons v0.0.0 => ../commons
	anyun.bitbucket.com/ntsc-lab-rpcpb v0.0.0 => ../ntsc-lab-rpcpb
	anyun.bitbucket.com/pkcs7 v0.0.0 => ../pkcs7
	anyun.bitbucket.com/timestamp v0.0.0 => ../timestamp
	github.com/coreos/bbolt v1.3.4 => go.etcd.io/bbolt v1.3.4
	github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.0.0
	go.etcd.io/bbolt v1.3.4 => github.com/coreos/bbolt v1.3.4
)
