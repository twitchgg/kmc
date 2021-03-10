package test

import (
	"fmt"
	"os"
	"testing"

	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(colorable.NewColorableStdout())
	formatter := new(prefixed.TextFormatter)
	logrus.SetFormatter(formatter)
}

func TestMain(m *testing.M) {
	fmt.Println("starting TSA KMC test")
	code := m.Run()
	if code != 0 {
		fmt.Println("\n##### test failed :( #####")
		os.Exit(code)
	}
	logrus.Info("test success!")
	os.Exit(0)
}
