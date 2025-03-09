package nmap

import (
	"fmt"
	"gammay/core/DP"
	"gammay/core/task"
	"gammay/utils"
	"gammay/utils/aliveCheck"
	"gammay/utils/logger"
	"gammay/utils/parse"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yqcs/fingerscan"
)

func Nmapinit(Tp *task.TaskPool) {
	if len(Tp.Params.Port) == 0 {
		Ports := "21,22,444,80,81,5040,4999,135,4630,139,443,445,1433,3306,5432,6379,8500,7001,8000,8080,8089,9000,9200,11211,27017,80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,61616,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880"
		Tp.Params.Port = parse.GetScanPort(Ports, Tp.Params.BlackPort)
	}
}

func Start(Tp *task.TaskPool, Nconfig *DP.NmapConfig) func() {

	return func() {

		var ipWg sync.WaitGroup
		ipWg.Add(len(Tp.Params.IP))
		for _, ip := range Tp.Params.IP {

			// 将 ip 作为参数传递给匿名函数，避免 Goroutine 共享变量
			go func(ip string) {
				defer ipWg.Done() // 确保每个 Goroutine 完成后减少计数器

				if aliveCheck.HostAliveCheck(ip, Nconfig.Ping, Tp.Params.Timeout, false) {
					// 增加 WaitGroup 计数器以跟踪端口扫描任务

					var portWg sync.WaitGroup
					portWg.Add(len(Tp.Params.Port))

					for _, port := range Tp.Params.Port {

						Tp.Scan.Pool.Submit(func() {
							defer portWg.Done()
							PortScan(Tp, net.JoinHostPort(ip, strconv.Itoa(port)))
						})
					}

					portWg.Wait() // 等待当前IP的所有端口完成
				}
			}(ip) // 调用匿名函数并传递 ip 参数
		}
		ipWg.Wait() // 等待所有 IP 的扫描完成
	}
}

func PortScan(Tp *task.TaskPool, i any) {
	//--------------------扫描主机存活--------------------------

	//检测存活端口

	if !aliveCheck.PortCheck(i.(string), Tp.Params.Timeout) {
		return
	}

	host, port, err := net.SplitHostPort(i.(string))
	if err != nil {
		return
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	//--------------------扫描指纹-------------------------

	//扫描指纹
	tcpFinger := fingerscan.ScanFingerprint(host, portInt, Tp.Params.Timeout+(5*time.Second))
	// if tcpFinger == nil {
	// 	return
	// }
	if tcpFinger == nil {
		return // 假设结构体名称为Finger
	}
	//不留存响应包
	tcpFinger.Response = nil
	if tcpFinger.Version.VendorProductName != "unknown" {
		//移除重复
		tcpFinger.WebApp.App = utils.DeleteSliceValueToLower(tcpFinger.WebApp.App, tcpFinger.Version.VendorProductName)
		//如果检测到了version，将其拼接进appName里，组成 nginx 1.18.2
		if tcpFinger.Version.Version != "unknown" {
			tcpFinger.WebApp.App = append(tcpFinger.WebApp.App, tcpFinger.Version.VendorProductName+" "+tcpFinger.Version.Version)
		} else {
			tcpFinger.WebApp.App = append(tcpFinger.WebApp.App, tcpFinger.Version.VendorProductName)
		}
	}

	//格式化输出指纹数据
	appString := ""
	for _, item := range tcpFinger.WebApp.App {
		appString += logger.Global.Color().Green(" [") + logger.Global.Color().CyanBg(item) + logger.Global.Color().Green("]")
	}
	if appString == "" {
		appString = " "
	}

	wsMsg := logger.Global.Color().GreenBg(fmt.Sprintf("%-"+strconv.Itoa(20)+"s", tcpFinger.Uri)) + "	" + "[" + logger.Global.Color().YellowBg(tcpFinger.Service) + "]" + "\t" + appString

	conMsg := net.JoinHostPort(host, port) + "\t" + tcpFinger.Service
	if tcpFinger.WebApp.App != nil {
		conMsg += " [" + strings.Join(tcpFinger.WebApp.App, ",") + "]"
	}

	if tcpFinger.WebApp.Title != "" {
		wsMsg += logger.Global.Color().Red("[") + tcpFinger.WebApp.Title + logger.Global.Color().Red("]")
		conMsg += " [" + tcpFinger.WebApp.Title + "]"
	}
	logger.ScanMessage(wsMsg)
}
