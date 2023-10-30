package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"os"
	"path/filepath"
)

// 加载证书并返回
func LoadCertificate2(derFile string) (*x509.Certificate, error) {
	certBuff, err := os.ReadFile(derFile)
	if err != nil {
		fmt.Println()
		fmt.Printf("ERROR: failed to read keystore file: %s, error: %s\n", derFile, err)
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBuff)
	if err != nil {
		//fmt.Printf("ERROR: failed get ECDSA private key, error: %v\n", err)
		return nil, err
	}

	return cert, nil
}

func load_midca() {
	midcaCertPath := "D:\\cslint\\cert_classificaton\\cert_db"
	midCertList, _ := os.ReadDir(midcaCertPath)

	var md5List []string
	for _, f := range midCertList {
		md5List = append(md5List, f.Name())
	}

	for _, md5 := range md5List {
		cert, err := LoadCertificate2(filepath.Join("D:\\cslint\\cert", md5))
		if err != nil {
			continue
		}
		midca[md5] = cert
	}
}
func Verify2(midCert, rootCert *x509.Certificate) error {
	if rootCert == nil || midCert == nil {
		return errors.New("null point")
	}
	if midCert.Issuer.CommonName != rootCert.Subject.CommonName {
		return errors.New("name not equal")
	}
	return rootCert.CheckSignature(midCert.SignatureAlgorithm, midCert.RawTBSCertificate, midCert.Signature)
}
func load_ccadb() {
	ccadbpath := "D:\\cslint\\cert_classificaton\\chain\\all_mid"
	ccadb_, _ := os.ReadDir(ccadbpath)
	var md5List []string
	for _, f := range ccadb_ {
		md5List = append(md5List, f.Name())
	}

	for _, md5 := range md5List {
		cert, _ := LoadCertificate2(filepath.Join("D:\\cslint\\cert", md5))
		ccadb[md5] = cert
	}
}

var ccadb map[string]*x509.Certificate
var midca map[string]*x509.Certificate

// var leaf map[string]*x509.Certificate
var root2mid []string

func init() {
	ccadb = make(map[string]*x509.Certificate)
	midca = make(map[string]*x509.Certificate)
	//leaf = make(map[string]*x509.Certificate)
	load_ccadb()
	load_midca()
	root2mid = []string{}
}

func root_find_mid() {
	for root_md5, root := range ccadb {
		for mid_md5, mid := range midca {
			err := Verify2(mid, root)
			if err == nil {
				root2mid = append(root2mid, root_md5+","+mid_md5)
			}
		}
	}
}

func main() {
	root_find_mid()
	file, err := os.Create("mid2leaf_new.txt")
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return
	}
	defer file.Close()

	// 使用bufio.NewWriter包装文件，以便按行写入数据
	writer := bufio.NewWriter(file)
	// 遍历map中的每个key和value列表
	for _, values := range root2mid {
		// 将value列表拼接成一个字符串

		// 写入key和value到文件中
		line := fmt.Sprintf("%s\n", values)
		_, err := writer.WriteString(line)
		if err != nil {
			fmt.Println("写入文件时出错:", err)
			return
		}
	}
	// 刷新缓冲区并检查是否有错误
	if err := writer.Flush(); err != nil {
		fmt.Println("刷新缓冲区时出错:", err)
		return
	}
}
