package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func loadCertificate(cerFile string) (*x509.Certificate, error) {
	certBuff, err := ioutil.ReadFile(cerFile)
	if err != nil {
		fmt.Println()
		fmt.Printf("ERROR: failed to read keystore file: %s, error: %s\n", cerFile, err)
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBuff)
	if err != nil {
		//fmt.Printf("ERROR: failed get ECDSA private key, error: %v\n", err)
		return nil, err
	}

	return cert, nil
}

func main() {
	// 指定目录路径
	dirPath := "D:\\cslint\\cert_classificaton\\leaf_cert\\all_trust_leaf_cert"

	// 用于存储颁发者和证书名的映射
	certificateMap := make(map[string][]string)

	// 遍历目录下的文件
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		fmt.Println("无法读取目录:", err)
		return
	}

	// 遍历每个文件
	for _, file := range files {

		// 读取证书文件内容
		cert, err := loadCertificate(filepath.Join(dirPath, file.Name()))
		if err != nil {
			fmt.Printf("无法读取文件 %s: %v\n", file.Name(), err)
			continue
		}

		// 使用颁发者的Common Name作为key，证书文件名作为value
		certificateMap[cert.Issuer.CommonName] = append(certificateMap[cert.Issuer.CommonName], file.Name())
	}

	// 输出到文件
	outputFile, err := os.Create("output_issue.txt")
	if err != nil {
		fmt.Println("无法创建输出文件:", err)
		return
	}
	defer outputFile.Close()

	for issuer, _ := range certificateMap {
		line := issuer + "\n"
		outputFile.WriteString(line)
	}

	fmt.Println("颁发者和证书名已写入output.txt")
}
