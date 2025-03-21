// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package quick

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	etcd "go.etcd.io/etcd/client/v3"
	yaml "gopkg.in/yaml.v3"
)

// ConfigEncoding is a generic interface which
// marshal/unmarshal configuration.
type ConfigEncoding interface {
	Unmarshal([]byte, interface{}) error
	Marshal(interface{}) ([]byte, error)
}

// YAML encoding implements ConfigEncoding
type yamlEncoding struct{}

func (y yamlEncoding) Unmarshal(b []byte, v interface{}) error {
	return yaml.Unmarshal(b, v)
}

func (y yamlEncoding) Marshal(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}

// JSON encoding implements ConfigEncoding
type jsonEncoding struct{}

func (j jsonEncoding) Unmarshal(b []byte, v interface{}) error {
	err := json.Unmarshal(b, v)
	if err != nil {
		// Try to return a sophisticated json error message if possible
		switch jerr := err.(type) {
		case *json.SyntaxError:
			return fmt.Errorf("Unable to parse JSON schema due to a syntax error at '%s'",
				FormatJSONSyntaxError(bytes.NewReader(b), jerr.Offset))
		case *json.UnmarshalTypeError:
			return fmt.Errorf("Unable to parse JSON, type '%v' cannot be converted into the Go '%v' type",
				jerr.Value, jerr.Type)
		}
		return err
	}
	return nil
}

func (j jsonEncoding) Marshal(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "\t")
}

// Convert a file extension to the appropriate struct capable
// to marshal/unmarshal data
func ext2EncFormat(fileExtension string) ConfigEncoding {
	// Lower the file extension
	ext := strings.ToLower(fileExtension)
	ext = strings.TrimPrefix(ext, ".")
	// Return the appropriate encoder/decoder according
	// to the extension
	switch ext {
	case "yml", "yaml":
		// YAML
		return yamlEncoding{}
	default:
		// JSON
		return jsonEncoding{}
	}
}

// toMarshaller returns the right marshal function according
// to the given file extension
func toMarshaller(ext string) func(interface{}) ([]byte, error) {
	return ext2EncFormat(ext).Marshal
}

// toUnmarshaller returns the right marshal function according
// to the given file extension
func toUnmarshaller(ext string) func([]byte, interface{}) error {
	return ext2EncFormat(ext).Unmarshal
}

// saveFileConfig marshals with the right encoding format
// according to the filename extension, if no extension is
// provided, json will be selected.
func saveFileConfig(filename string, v interface{}) error {
	// Fetch filename's extension
	ext := filepath.Ext(filename)
	// Marshal data
	dataBytes, err := toMarshaller(ext)(v)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		dataBytes = []byte(strings.Replace(string(dataBytes), "\n", "\r\n", -1))
	}
	// Save data.
	return writeFile(filename, dataBytes)
}

func saveFileConfigEtcd(filename string, clnt *etcd.Client, v interface{}) error {
	// Fetch filename's extension
	ext := filepath.Ext(filename)
	// Marshal data
	dataBytes, err := toMarshaller(ext)(v)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		dataBytes = []byte(strings.Replace(string(dataBytes), "\n", "\r\n", -1))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = clnt.Put(ctx, filename, string(dataBytes))
	if err == context.DeadlineExceeded {
		return fmt.Errorf("etcd setup is unreachable, please check your endpoints %s", clnt.Endpoints())
	} else if err != nil {
		return fmt.Errorf("unexpected error %w returned by etcd setup, please check your endpoints %s", err, clnt.Endpoints())
	}
	return nil
}

func loadFileConfigEtcd(filename string, clnt *etcd.Client, v interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := clnt.Get(ctx, filename)
	if err != nil {
		if err == context.DeadlineExceeded {
			return fmt.Errorf("etcd setup is unreachable, please check your endpoints %s", clnt.Endpoints())
		}
		return fmt.Errorf("unexpected error %w returned by etcd setup, please check your endpoints %s", err, clnt.Endpoints())
	}
	if resp.Count == 0 {
		return os.ErrNotExist
	}

	for _, ev := range resp.Kvs {
		if string(ev.Key) == filename {
			fileData := ev.Value
			if runtime.GOOS == "windows" {
				fileData = bytes.Replace(fileData, []byte("\r\n"), []byte("\n"), -1)
			}
			// Unmarshal file's content
			return toUnmarshaller(filepath.Ext(filename))(fileData, v)
		}
	}
	return os.ErrNotExist
}

// loadFileConfig unmarshals the file's content with the right
// decoder format according to the filename extension. If no
// extension is provided, json will be selected by default.
func loadFileConfig(filename string, v interface{}) error {
	// sobug 解密
	if err := DecryptFile(filename); err != nil {
		log.Panicln("decryptFile the alias config file error.", err)
	}
	defer EncryptFile(filename) // 重新加密

	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		fileData = []byte(strings.Replace(string(fileData), "\r\n", "\n", -1))
	}

	// Unmarshal file's content
	return toUnmarshaller(filepath.Ext(filename))(fileData, v)
}

var encryptionKey = []byte("d7#kL9!mQ2pZ$5vR")

// 密钥派生函数（增强安全性）
func deriveKey(rawKey []byte) []byte {
	hash := sha256.Sum256(rawKey)
	return hash[:16] // 使用前16字节作为AES-128密钥
}

// 定义加密文件头标识（4字节魔数 + 1字节版本号）
const (
	magicNumber = "ENC"                // 3字节固定标识
	currentVer  = 0x01                 // 1字节版本号
	headerSize  = len(magicNumber) + 1 // 总头长度=4字节
)

func EncryptFile(filePath string) error {
	// 1. 预检文件状态
	existing, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	// 2. 检查是否已加密
	if len(existing) >= headerSize &&
		string(existing[0:3]) == magicNumber {
		return nil // 已加密文件直接跳过
	}

	// 3. 执行加密流程
	block, _ := aes.NewCipher(deriveKey(encryptionKey))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("创建GCM失败: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return fmt.Errorf("生成随机数失败: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, existing, nil)

	// 4. 构建带标识的加密文件
	header := make([]byte, headerSize)
	copy(header[0:3], magicNumber)
	header[3] = currentVer

	finalData := append(header, nonce...)
	finalData = append(finalData, ciphertext...)

	// 5. 原子写入（避免写入中途失败导致文件损坏）
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, finalData, 0644); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	return os.Rename(tmpPath, filePath)
}

func DecryptFile(filePath string) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("解密过程发生panic：%v", r)
		}
	}()

	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	// 1. 基础长度校验
	if len(ciphertext) < headerSize {
		return nil // 非加密文件直接跳过
	}

	// 2. 验证加密标识
	header := ciphertext[0:headerSize]
	if string(header[0:3]) != magicNumber {
		return nil // 非加密文件静默跳过
	}

	// 3. 提取加密参数
	nonceSize := 12 // GCM标准Nonce长度
	payload := ciphertext[headerSize:]
	if len(payload) < nonceSize {
		return fmt.Errorf("文件损坏：无效长度")
	}

	nonce := payload[0:nonceSize]
	ciphertext = payload[nonceSize:]

	// 4. 执行解密
	block, _ := aes.NewCipher(deriveKey(encryptionKey))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("创建GCM失败: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("解密失败: %w", err)
	}

	// 5. 安全写入（保持原权限）
	fi, _ := os.Stat(filePath)
	return os.WriteFile(filePath, plaintext, fi.Mode().Perm())
}
