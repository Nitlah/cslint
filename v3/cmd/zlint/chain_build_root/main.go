package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"os"
	"path/filepath"
	"strings"
)

// 加载证书并返回
func loadCertificate(derFile string) (*x509.Certificate, error) {
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

// 加载叶证书
func loadLeafCertificate() map[string]*x509.Certificate {
	leafCertPath := "D:\\cslint\\cert_classificaton\\chain\\leaf"
	leafCertList, _ := os.ReadDir(leafCertPath)

	var md5List []string
	for _, f := range leafCertList {
		md5List = append(md5List, f.Name())
	}

	CertList := make(map[string]*x509.Certificate)
	for _, md5 := range md5List {
		cert, _ := loadCertificate(filepath.Join("D:\\cslint\\cert", md5))
		CertList[md5] = cert
	}
	return CertList
}

// 根证书
func loadRootCertificate() map[string]*x509.Certificate {
	rootCafiles, _ := os.ReadDir("D:\\cslint\\cert_classificaton\\self_signed_cert\\ccadb_cer")
	var md5List []string
	for _, f := range rootCafiles {
		md5List = append(md5List, f.Name())
	}
	CAList := make(map[string]*x509.Certificate)
	for _, md5 := range md5List {
		cert, _ := loadCertificate(filepath.Join("D:\\cslint\\cert", md5))
		CAList[md5] = cert
	}
	return CAList
}

// 中间证书
func loadMidCertificate() map[string]*x509.Certificate {
	midCafiles, _ := os.ReadDir("D:\\cslint\\cert_classificaton\\chain\\all_mid")
	var md5List []string
	for _, f := range midCafiles {
		md5List = append(md5List, f.Name())
	}
	CAList := make(map[string]*x509.Certificate)
	for _, md5 := range md5List {
		cert, _ := loadCertificate(filepath.Join("D:\\cslint\\cert", md5))
		CAList[md5] = cert
	}
	return CAList
}

func Verify(son_md5 string, son *x509.Certificate, father_md5 string, father *x509.Certificate, save bool) (bool, error) {
	if save == true {
		if val, ok := memo[son_md5+father_md5]; ok {
			return val, nil
		}
	}

	if father == nil || son == nil {
		if save == true {
			memo[son_md5+father_md5] = false
		}
		return false, errors.New("null point")
	}
	if !bytes.Equal(father.RawSubject, son.RawIssuer) {
		if save == true {
			memo[son_md5+father_md5] = false
		}
		return false, errors.New("name not equal")
	}

	err := father.CheckSignature(son.SignatureAlgorithm, son.RawTBSCertificate, son.Signature)
	if err != nil {
		if save == true {
			memo[son_md5+father_md5] = false
		}
		return false, err
	} else {
		if save == true {
			memo[son_md5+father_md5] = true
		}
		return true, nil
	}
}

var rootCert map[string]*x509.Certificate
var midCert map[string]*x509.Certificate
var leafCert map[string]*x509.Certificate
var data [][]string
var memo map[string]bool

func init() {
	rootCert = loadRootCertificate()
	midCert = loadMidCertificate()
	leafCert = loadLeafCertificate()
	memo = make(map[string]bool)
	data = [][]string{}
	fmt.Println("数据初始化完毕")
}

func buildChain() {
	c := 0
	for leaf_md5, leaf_c := range leafCert {
		c += 1
		if c%100 == 0 {
			fmt.Println(c)
		}
		for mid_md5, mid_c := range midCert {
			if ok1, _ := Verify(leaf_md5, leaf_c, mid_md5, mid_c, false); ok1 == false {
				continue
			}
			for root_md5, root_c := range rootCert {
				if ok2, _ := Verify(mid_md5, mid_c, root_md5, root_c, true); ok2 == true {
					data = append(data, []string{leaf_md5, mid_md5, root_md5})
				}
			}
		}
	}
}

func main() {
	buildChain()
	// 打开文件以写入数据
	file, err := os.Create("chain_10_17_3.txt")
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return
	}
	defer file.Close()

	// 使用bufio.NewWriter包装文件，以便按行写入数据
	writer := bufio.NewWriter(file)
	// 遍历map中的每个key和value列表
	for _, values := range data {
		// 将value列表拼接成一个字符串
		valueStr := strings.Join(values, ", ")

		// 写入key和value到文件中
		line := fmt.Sprintf("%s\n", valueStr)
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

	fmt.Println("数据已成功写入文件.")
}
