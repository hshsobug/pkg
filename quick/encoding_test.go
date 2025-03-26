package quick

// // EncryptWorker 用于加密文件
// func EncryptWorker(filePath string, wg *sync.WaitGroup, errChan chan error) {
// 	defer wg.Done()
// 	if err := EncryptFile(filePath); err != nil {
// 		errChan <- err
// 	}
// }

// // DecryptWorker 用于解密文件
// func DecryptWorker(filePath string, wg *sync.WaitGroup, errChan chan error) {
// 	defer wg.Done()
// 	if err := DecryptFile(filePath); err != nil {
// 		errChan <- err
// 	}
// }

// // TestMultiProcessEncryptDecrypt 测试多个程序对同一文件加密解密
// func TestMultiProcessEncryptDecrypt(t *testing.T) {
// 	// 准备测试数据
// 	data := make([]byte, 1024)
// 	rand.Read(data)

// 	// 创建临时文件
// 	filePath := filepath.Join(t.TempDir(), "testfile.dat")
// 	if err := os.WriteFile(filePath, data, 0644); err != nil {
// 		t.Fatalf("无法写入测试文件: %v", err)
// 	}

// 	// 定义模拟的程序数量
// 	numProcesses := 5

// 	var wg sync.WaitGroup
// 	errChan := make(chan error, numProcesses*2) // 每个程序进行一次加密和一次解密

// 	// 启动多个 goroutine 模拟多个程序
// 	for i := 0; i < numProcesses; i++ {
// 		wg.Add(2)
// 		go EncryptWorker(filePath, &wg, errChan)
// 		go DecryptWorker(filePath, &wg, errChan)
// 	}

// 	// 等待所有 goroutine 完成
// 	go func() {
// 		wg.Wait()
// 		close(errChan)
// 	}()

// 	// 检查是否有错误发生
// 	for err := range errChan {
// 		if err != nil {
// 			t.Fatalf("加密或解密失败: %v", err)
// 		}
// 	}
// }
