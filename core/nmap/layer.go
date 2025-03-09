package nmap

import (
	"bufio"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"gammay/core/DP"
	"gammay/utils/logger"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 优先级队列实现
type PriorityQueue []*ScanTask

func (pq PriorityQueue) Len() int           { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool { return pq[i].Weight > pq[j].Weight } // 最大堆
func (pq PriorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*ScanTask)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

// 扫描任务结构
type ScanTask struct {
	Path     string
	Depth    int
	Weight   int  // 权重值（0-100）
	IsDir    bool // 是否为目录
	priority int  // 内部优先级
}

// 目录扫描器
type DirScanner struct {
	baseURL       *url.URL
	client        *http.Client
	queue         *PriorityQueue
	queueMutex    sync.Mutex
	visited       sync.Map
	extGenerators []ExtensionGenerator
	weightRules   []WeightRule
	config        DP.ScannerConfig
}

// 扩展名生成器类型
type ExtensionGenerator func(base string) []string

// 权重计算规则类型
type WeightRule func(path string, depth int) int

// 初始化扫描器
func ScannerInit(Tp DP.ScanParams, config *DP.ScannerConfig) (*DirScanner, error) {
	rawURL := Tp.Domain[0]
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL // 默认使用 HTTP，或根据需求调整
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	// 初始化HTTP客户端
	transport := &http.Transport{
		MaxIdleConns:       config.Threads * 2,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
		MaxConnsPerHost:    config.Threads,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	scanner := &DirScanner{
		baseURL: u,
		client:  client,
		queue:   &PriorityQueue{},
		config:  *config,
	}

	// 初始化扩展生成器
	scanner.initExtensionGenerators()
	// 初始化权重规则
	scanner.initWeightRules()
	//将满足 heap.Interface 接口的切片或数据结构初始化为一个堆
	heap.Init(scanner.queue)
	return scanner, nil
}

// 初始化扩展生成规则
func (d *DirScanner) initExtensionGenerators() {
	d.extGenerators = []ExtensionGenerator{
		// 基础备份扩展
		func(base string) []string {
			return []string{base + ".bak", base + ".old", base + ".backup"}
		},
		// 时间戳扩展
		func(base string) []string {
			ts := time.Now().Format("20060102")
			return []string{
				fmt.Sprintf("%s_%s", base, ts),
				fmt.Sprintf("%s.%s", base, ts),
			}
		},
		// 版本号扩展
		func(base string) []string {
			return []string{
				base + ".v1",
				base + "_v2",
				base + "-latest",
			}
		},
		// 压缩格式扩展
		func(base string) []string {
			return []string{
				base + ".zip",
				base + ".tar.gz",
				base + ".7z",
			}
		},
	}
}

// 初始化权重规则
func (d *DirScanner) initWeightRules() {
	d.weightRules = []WeightRule{
		// 路径深度权重
		func(path string, depth int) int {
			return 100 - depth*10
		},
		// 常见路径权重
		func(path string, _ int) int {
			commonPaths := map[string]int{
				"admin":    90,
				"wp-admin": 85,
				"backup":   80,
				"config":   75,
				"api":      70,
				"v1":       65,
				"test":     60,
				"tmp":      55,
			}
			base := filepath.Base(path)
			if score, exists := commonPaths[base]; exists {
				return score
			}
			return 50
		},
		// 扩展名权重
		func(path string, _ int) int {
			ext := filepath.Ext(path)
			extWeights := map[string]int{
				".php":  85,
				".asp":  80,
				".conf": 75,
				".bak":  90,
				".sql":  95,
			}
			return extWeights[ext]
		},
	}
}

// 计算路径权重
func (d *DirScanner) calculateWeight(path string, depth int) int {
	maxWeight := 0
	for _, rule := range d.weightRules {
		weight := rule(path, depth)
		if weight > maxWeight {
			maxWeight = weight
		}
	}
	return maxWeight
}

// 生成路径变体
func (d *DirScanner) generateVariants(basePath string) []string {
	variants := make(map[string]struct{})

	// 基础路径
	variants[basePath] = struct{}{}

	// 扩展名变体
	for _, gen := range d.extGenerators {
		for _, ext := range gen(basePath) {
			variants[ext] = struct{}{}
		}
	}

	// 目录变体
	variants[basePath+"/"] = struct{}{}
	variants[strings.TrimSuffix(basePath, "/")] = struct{}{}

	// 去重后返回
	result := make([]string, 0, len(variants))
	for k := range variants {
		result = append(result, k)
	}
	return result
}

// 添加任务到优先级队列
func (d *DirScanner) addTask(path string, depth int, isDir bool) {
	if depth > d.config.MaxDepth {
		return
	}

	// 生成路径变体
	variants := d.generateVariants(path)

	for _, variant := range variants {
		// 检查是否已访问
		if _, exists := d.visited.Load(variant); exists {
			continue
		}
		d.visited.Store(variant, struct{}{})

		// 计算权重
		weight := d.calculateWeight(variant, depth)

		// 创建任务
		task := &ScanTask{
			Path:   variant,
			Depth:  depth + 1,
			Weight: weight,
			IsDir:  isDir,
		}

		d.queueMutex.Lock()
		heap.Push(d.queue, task)
		d.queueMutex.Unlock()
	}
}

// 工作线程
func (d *DirScanner) worker(ctx context.Context, results chan<- string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			task := d.getNextTask()
			if task == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// 发送请求
			fullURL := d.baseURL.ResolveReference(&url.URL{Path: task.Path}).String()
			resp, err := d.doRequest(ctx, fullURL)
			if err == nil && d.isValidResponse(resp) {
				results <- fullURL

				// 发现有效路径后动态调整权重
				if task.IsDir {
					d.adjustWeights(task.Path)
				}
			}

			// 处理递归扫描
			if resp != nil && resp.StatusCode == 200 && task.IsDir {
				d.addTask(task.Path+"/", task.Depth, true)
			}
		}
	}
}

// 获取下一个任务（带优先级）
func (d *DirScanner) getNextTask() *ScanTask {
	d.queueMutex.Lock()
	defer d.queueMutex.Unlock()

	if d.queue.Len() == 0 {
		return nil
	}

	task := heap.Pop(d.queue).(*ScanTask)
	return task
}

// 执行HTTP请求
func (d *DirScanner) doRequest(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 随机User-Agent
	if len(d.config.UserAgents) > 0 {
		req.Header.Set("User-Agent", d.config.UserAgents[rand.Intn(len(d.config.UserAgents))])
	}

	// 重试逻辑
	var resp *http.Response
	for i := 0; i < d.config.Retries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			resp, err = d.client.Do(req)
			if err == nil {
				return resp, nil
			}
		}
	}
	return nil, err
}

// 验证响应有效性
func (d *DirScanner) isValidResponse(resp *http.Response) bool {
	// 检查状态码
	validStatus := false
	for _, s := range d.config.MatchStatus {
		if resp.StatusCode == s {
			validStatus = true
			break
		}
	}
	if !validStatus {
		return false
	}

	// 检查内容长度
	if resp.ContentLength == 0 {
		return false
	}

	// 检查内容类型
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "image/") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "application/javascript") {
		return false
	}

	return true
}

// 动态调整权重规则
func (d *DirScanner) adjustWeights(foundPath string) {
	// 根据发现的路径增加相关路径的权重
	base := filepath.Base(foundPath)

	// 示例调整规则：
	// 发现admin目录时，增加类似管理路径的权重
	if strings.Contains(base, "admin") {
		d.weightRules = append(d.weightRules, func(path string, _ int) int {
			if strings.Contains(path, "admin") ||
				strings.Contains(path, "manage") ||
				strings.Contains(path, "control") {
				return 95
			}
			return 0
		})
	}
}

// 启动扫描
func (d *DirScanner) Run(ctx context.Context, initialPaths []string) <-chan string {
	results := make(chan string, 100)

	// 初始化队列
	for _, path := range initialPaths {
		d.addTask(path, 0, true)
	}

	// 启动工作线程
	for i := 0; i < d.config.Threads; i++ {
		go d.worker(ctx, results)
	}

	return results
}
func LayerConfigInit(Tp DP.ScanParams, Timeout int, MatchStatus []int) *DP.ScannerConfig {

	var LayerConfig = &DP.ScannerConfig{
		MaxDepth:      3,
		Timeout:       10 * time.Second,
		UserAgents:    []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		Threads:       20,
		MatchStatus:   []int{200, 301, 302, 403},
		Retries:       1,
		RandomDelay:   500 * time.Millisecond,
		MaxQueueSize:  10000,
		BackupPattern: []string{".bak", ".old", ".backup"},
	}

	if Timeout != 0 {
		LayerConfig.Timeout = time.Duration(Timeout) * time.Minute
	}
	if MatchStatus != nil {
		LayerConfig.MatchStatus = MatchStatus
	}
	if Tp.Thread != 0 {
		LayerConfig.Threads = Tp.Thread
	}
	return LayerConfig
}

func Layermain(Tp DP.ScanParams, LC *DP.ScannerConfig) {
	scanner, err := ScannerInit(Tp, LC)
	if err != nil {
		panic(err)
	}
	//创建一个带有超时机制的上下文（Context）​。这个上下文会在指定的时间（10 分钟）后自动取消，并通知所有使用该上下文的 goroutine 停止当前操作。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	file, err := os.Open("core/nmap/static/layerdict.txt")
	if err != nil {
		logger.Error("Failed to open dictionary file")
		panic(err)
	}
	defer file.Close()
	a := bufio.NewScanner(file)

	// 初始种子路径
	initialPaths := []string{}
	// 逐行读取文件内容
	for a.Scan() {
		initialPaths = append(initialPaths, a.Text())
	}
	resultChan := scanner.Run(ctx, initialPaths)

	// 处理结果
	for result := range resultChan {
		fmt.Printf("[FOUND] %s\n", result)
	}
}

func DelegateTask(suffix []int, pathChan chan<- string, ctx context.Context) func() {
	return func() {
		var loadWG sync.WaitGroup
		loadWG.Add(1)
		go func() {
			defer loadWG.Done() // 字典加载完成
			defer close(pathChan)
			seen := make(map[string]struct{}) // 内存去重

			// 按后缀顺序加载文件
			for _, s := range suffix {
				select {
				case <-ctx.Done():
					return // 及时响应取消信号
				default:
				}
				filePath := getDictPath(s)
				file, err := os.Open(filePath)
				if err != nil {
					logger.Error("打开字典文件失败: "+filePath, err)
					continue
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				var count int
				for scanner.Scan() {
					// 检查上下文取消
					select {
					case <-ctx.Done():
						file.Close()
						return
					default:
					}

					path := strings.TrimSpace(scanner.Text())
					if path == "" {
						continue
					}

					// 内存去重
					if _, exists := seen[path]; !exists {
						seen[path] = struct{}{}
						count++

						// 非阻塞发送路径
						select {
						case pathChan <- path:
						default:

							time.Sleep(100 * time.Millisecond)
							pathChan <- path
						case <-ctx.Done():
							return
						}
						// 每1000条记录日志
						if count%1000 == 0 {
							logger.Info(fmt.Sprintf("[%s] 已加载 %d 条路径", filePath, count))
						}
					}
				}
				// 处理扫描错误
				if err := scanner.Err(); err != nil {
					logger.Error("文件读取错误: "+filePath, err)
				}

			}
		}()
		loadWG.Wait()
	}
}

func NormalLayermain(Tp DP.ScanParams, ctx context.Context, pathChan <-chan string, scanner *DirScanner) func() {
	return func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, Tp.Thread) // 控制并发量
		// 启动结果处理监控
	loop:
		for {
			select {
			case path, ok := <-pathChan:
				if !ok { // 通道已关闭且无数据
					break loop
				}

				wg.Add(1)
				sem <- struct{}{}

				go func(p string) {
					defer func() {
						<-sem
						wg.Done()
					}()
					// 发送带上下文的请求
					fullURL := scanner.baseURL.ResolveReference(&url.URL{Path: p}).String()
					resp, err := scanner.doRequest(ctx, fullURL)
					if err != nil {
						if !errors.Is(err, context.Canceled) {
						}
						return

					}
					defer resp.Body.Close()
					if scanner.isValidResponse(resp) {
						logFoundResult(scanner.config.MatchStatus, resp.StatusCode, fullURL)
					}
				}(path)
			case <-ctx.Done():
				break loop
			}
		}
		wg.Wait()
	}
}

// func NormalLayermain(Tp DP.ScanParams, LC *DP.ScannerConfig, suffix []int) func() {
// 	pathChan := make(chan string, 1000)
// 	scanner, err := ScannerInit(Tp, LC)
// 	if err != nil {
// 		panic(err)
// 	}

// 	//创建一个带有超时机制的上下文（Context）​。这个上下文会在指定的时间（10 分钟）后自动取消，并通知所有使用该上下文的 goroutine 停止当前操作。
// 	ctx, cancel := context.WithTimeout(context.Background(), LC.Timeout)

// 	var loadWG sync.WaitGroup
// 	loadWG.Add(1)
// 	go func() {
// 		defer loadWG.Done() // 字典加载完成
// 		defer close(pathChan)
// 		seen := make(map[string]struct{}) // 内存去重

// 		// 按后缀顺序加载文件
// 		for _, s := range suffix {
// 			select {
// 			case <-ctx.Done():
// 				return // 及时响应取消信号
// 			default:}
// 				filePath := getDictPath(s)
// 				file, err := os.Open(filePath)
// 				if err != nil {
// 					logger.Error("打开字典文件失败: "+filePath, err)
// 					continue
// 				}
// 				// defer file.Close()

// 				scanner := bufio.NewScanner(file)
// 				var count int
// 				for scanner.Scan() {
// 					// 检查上下文取消
// 					select {
// 					case <-ctx.Done():
// 						file.Close()
// 						return
// 					default:
// 					}

// 					path := strings.TrimSpace(scanner.Text())
// 					if path == "" {
// 						continue
// 					}

// 					// 内存去重
// 					if _, exists := seen[path]; !exists {
// 						seen[path] = struct{}{}
// 						count++

// 						// 非阻塞发送路径
// 						select {
// 						case pathChan <- path:
// 							logger.Infof("扫描3")
// 						default:
// 							// 通道已满，等待一段时间后重试
// 							logger.Infof("通道已满，等待一段时间后重试")
// 							time.Sleep(100 * time.Millisecond)
// 							pathChan <- path
// 						case <-ctx.Done():
// 							return
// 						}
// 						// 每1000条记录日志
// 						if count%1000 == 0 {
// 							logger.Info(fmt.Sprintf("[%s] 已加载 %d 条路径", filePath, count))
// 						}
// 					}
// 				}
// 				file.Close()
// 				// 处理扫描错误
// 				if err := scanner.Err(); err != nil {
// 					logger.Error("文件读取错误: "+filePath, err)
// 				}

// 		}
// 	}()
// 	//
// 	return func() {
// 		loadWG.Wait()  // 等待字典加载完成
// 		defer cancel() // 释放上下文
// 		var wg sync.WaitGroup
// 		sem := make(chan struct{}, Tp.Thread) // 控制并发量
// 		// 启动结果处理监控
// 		logger.Infof("扫描1")
// 		for path := range pathChan {
// 			logger.Infof("扫描2")
// 			// 检查上下文状态
// 			select {
// 			case <-ctx.Done():
// 				logger.Infof("上下文取消，原因：" + ctx.Err().Error())
// 				return
// 			default:
// 			}
// 			logger.Infof("正在扫描路径: " + path)
// 			sem <- struct{}{} // 控制并发
// 			wg.Add(1)         // 任务计数
// 			go func(p string) {

// 				defer func() {
// 					<-sem     // 释放信号量
// 					wg.Done() // 任务完成
// 				}()

// 				// 发送带上下文的请求
// 				fullURL := scanner.baseURL.ResolveReference(&url.URL{Path: p}).String()
// 				resp, err := scanner.doRequest(ctx, fullURL)
// 				logger.Infof(path + resp.Status)
// 				if err != nil {
// 					if !errors.Is(err, context.Canceled) {
// 						logger.Debug("请求失败: " + fullURL)
// 					}
// 					return
// 				}
// 				defer resp.Body.Close()

// 				if scanner.isValidResponse(resp) {
// 					logFoundResult(resp.StatusCode, fullURL)

// 				}
// 			}(path)
// 		}

// 		defer func() {
// 			// 等待所有任务完成
// 			close(sem)
// 		}()
// 		wg.Wait()
// 	}

// }

func getDictPath(suffix int) string {
	suffixMap := map[int]string{
		1: "core/nmap/static/php.txt",
		2: "core/nmap/static/jsp.txt",
		3: "core/nmap/static/dir.txt",
		4: "core/nmap/static/aspx.txt",
		5: "core/nmap/static/mdb.txt",
		6: "core/nmap/static/asp.txt",
	}
	return suffixMap[suffix]
}

func logFoundResult(MatchStatus []int, statusCode int, url string) {
	color := logger.Global.Color()
	statusStr := fmt.Sprintf("%d", statusCode)

	var msg string
	switch {
	case statusCode == MatchStatus[0]:
		msg = color.GreenBg("[FOUND] ") + color.BlueBg(url) + color.GreenBg(statusStr)
	case statusCode == MatchStatus[1]:
		msg = color.YellowBg("[FOUND] ") + url + color.Yellow(statusStr)
		// default:
		// 	msg = color.BlueBg("[FOUND] ") + url + color.Blue(statusStr)
	}

	logger.Info(msg)
}
