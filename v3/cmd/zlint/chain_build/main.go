package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/zmap/zcrypto/x509"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 加载证书并返回
func LoadCertificate(derFile string) (*x509.Certificate, error) {
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
func loadAllCertificate() {
	leafCertPath := "D:\\cslint\\cert_classificaton\\cert_db"
	//leafCertPath := "D:\\cslint\\cert_classificaton\\leaf_cert\\all_trust_leaf_cert"
	//leafCertPath := "D:\\cslint\\cert_classificaton\\lab\\leaf"
	leafCertList, _ := os.ReadDir(leafCertPath)

	var md5List []string
	for _, f := range leafCertList {
		md5List = append(md5List, f.Name())
	}

	for _, md5 := range md5List {
		cert, err := LoadCertificate(filepath.Join("D:\\cslint\\cert", md5))
		if err != nil {
			continue
		}
		if !cert.IsCA && !cert.SelfSigned {
			leafCert[md5] = cert
		} else {
			allCACert[md5] = cert
		}
	}
}

func Verify(midCert, rootCert *x509.Certificate) error {
	if rootCert == nil || midCert == nil {
		return errors.New("null point")
	}
	if midCert.Issuer.CommonName != rootCert.Subject.CommonName {
		return errors.New("name not equal")
	}
	return rootCert.CheckSignature(midCert.SignatureAlgorithm, midCert.RawTBSCertificate, midCert.Signature)
}

func contain(chain []string, md5 string) bool {
	for _, item := range chain {
		if md5 == item {
			return true
		}
	}
	return false
}

func buildChain() bool {
	var cert *x509.Certificate
	endMD5 := chain[len(chain)-1]
	if len(chain) > 1 {
		cert = allCACert[endMD5]
	} else {
		cert = leafCert[endMD5]
	}

	//if len(chain) >= 4 {
	//	fmt.Println("break")
	//}
	for md5, root := range allCACert {
		if contain(chain, md5) {
			continue
		}
		err := Verify(cert, root)
		if err == nil {
			if root.SelfSigned {
				chain = append(chain, md5)
				return true
			}
			chain = append(chain, md5)
			if buildChain() {
				return true
			} else {
				// 链构建失败回退
				chain = chain[:len(chain)-1]
			}
		}
	}
	return false
}

var allCACert map[string]*x509.Certificate
var leafCert map[string]*x509.Certificate
var chain []string

func init() {
	fmt.Println("：加载数据,当前时间", time.Now())
	allCACert = make(map[string]*x509.Certificate)
	leafCert = make(map[string]*x509.Certificate)

	loadAllCertificate()
	chain = []string{}

	fmt.Println("加载完毕,当前时间：", time.Now())
	fmt.Println("ca count:", len(allCACert))
	fmt.Println("leaf count:", len(leafCert))

}

func main() {
	data := map[string][]string{}
	otherData := map[string][]string{}
	c := 0
	for k1, _ := range leafCert {
		c += 1
		if c%500 == 0 {
			fmt.Println("当前时间：", time.Now(), c)
		}
		//if c == 500 {
		//	break
		//}
		chain = []string{k1}
		if buildChain() {
			data[k1] = chain
		} else {
			otherData[k1] = chain
		}
	}
	fmt.Println("数据运行完成,当前时间：", time.Now())
	// 打开文件以写入数据chain.txt
	file, err := os.Create("chain.txt")
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

	otherfile, err := os.Create("otherchain.txt")
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return
	}
	defer otherfile.Close()
	otherwriter := bufio.NewWriter(otherfile)
	// 遍历map中的每个key和value列表
	for _, values := range otherData {
		// 将value列表拼接成一个字符串
		valueStr := strings.Join(values, ", ")

		// 写入key和value到文件中
		line := fmt.Sprintf("%s\n", valueStr)
		_, err := otherwriter.WriteString(line)
		if err != nil {
			fmt.Println("写入文件时出错:", err)
			return
		}
	}
	// 刷新缓冲区并检查是否有错误
	if err := otherwriter.Flush(); err != nil {
		fmt.Println("刷新缓冲区时出错:", err)
		return
	}

	fmt.Println("数据已成功写入文件.")
}
