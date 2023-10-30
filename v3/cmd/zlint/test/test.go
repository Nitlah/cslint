package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/util"
	"io"
	"os"
	"path/filepath"
)

func main() {
	dir := "D:\\cslint\\mix_cert" // 当前目录
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 如果是文件或目录（排除目录本身）
		if info.Mode().IsRegular() || (info.Mode()&os.ModeType) == os.ModeDir && path != dir {
			//
			//fmt.Println(path)
			_, filename := filepath.Split(path)
			inputFile, err := os.Open(path)
			if err != nil {
				log.Fatalf("unable to open file %s: %s", path, err)
			}
			defer inputFile.Close()

			fileBytes, err := io.ReadAll(inputFile)
			if err != nil {
				log.Fatalf("unable to read file %s: %s", inputFile.Name(), err)
			}
			c, err := x509.ParseCertificate(fileBytes)
			if err != nil {
				_, err := CopyFile(path, filepath.Join("D:\\cslint\\error_cert", filename))
				if err != nil {
					return err
				}
				log.Debugf("unable to parse certificate: %s", err)
				return nil
			}
			// 将eku添加到map中
			ekuFields := make(map[x509.ExtKeyUsage]int)
			if c.ExtKeyUsage != nil {
				for _, v := range c.ExtKeyUsage {
					ekuFields[v] = 1
				}
			}

			// 证书分类 中间证书、叶证书
			if c.IsCA {
				if ekuFields[x509.ExtKeyUsageTimeStamping] == 1 && ekuFields[x509.ExtKeyUsageCodeSigning] == 1 {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\sub_ca\\both", filename))
					if err != nil {
						return err
					}
				} else if ekuFields[x509.ExtKeyUsageTimeStamping] == 1 {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\sub_ca\\time_stamping", filename))
					if err != nil {
						return err
					}
				} else if ekuFields[x509.ExtKeyUsageCodeSigning] == 1 {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\sub_ca\\code_signing", filename))
					if err != nil {
						return err
					}
				} else {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\sub_ca\\other", filename))
					if err != nil {
						return err
					}
				}
			} else if util.IsSubscriberCert(c) {
				if ekuFields[x509.ExtKeyUsageTimeStamping] == 1 && ekuFields[x509.ExtKeyUsageCodeSigning] == 1 {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\leaf_cert\\both", filename))
					if err != nil {
						return err
					}
				} else if ekuFields[x509.ExtKeyUsageTimeStamping] == 1 {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\leaf_cert\\time_stamping", filename))
					if err != nil {
						return err
					}
				} else if ekuFields[x509.ExtKeyUsageCodeSigning] == 1 {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\leaf_cert\\code_signing", filename))
					if err != nil {
						return err
					}
				} else {
					_, err := CopyFile(path, filepath.Join("D:\\cslint\\cert_classificaton\\leaf_cert\\other", filename))
					if err != nil {
						return err
					}
				}
			} else {
				fmt.Printf("other cert %s\n", path)
			}

		}

		return nil
	})

	if err != nil {
		fmt.Println("Error:", err)
	}
}

func CopyFile(srcName, dstName string) (written int64, err error) {
	src, err := os.Open(srcName)
	if err != nil {
		return
	}
	defer src.Close()

	dst, err := os.OpenFile(dstName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer dst.Close()

	return io.Copy(dst, src)
}
