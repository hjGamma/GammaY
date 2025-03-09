package cmd

//待添加功能
// 1.域名转换IP进行端口指纹探测以及bypassCDN
// 2.C段探测，根据提交的掩码进行C段探测
import (
	"context"
	"fmt"
	"gammay/core/DP"
	"gammay/core/nmap"
	"gammay/core/task"
	"gammay/utils/logger"
	"time"

	"github.com/spf13/cobra"
)

var nmapCmd = &cobra.Command{
	Use:   "nmap",
	Short: "IP fingerprinting and subdomain detection",
	Long: `
 ██████╗     █████╗     ███╗   ███╗    ███╗   ███╗     █████╗     ██╗   ██╗
██╔════╝    ██╔══██╗    ████╗ ████╗    ████╗ ████╗    ██╔══██╗    ╚██╗ ██╔╝
██║  ███╗   ███████║    ██╔████╔██╗NMAP██╔████╔██╗    ███████║     ╚████╔╝ 
██║   ██║   ██╔══██║    ██║╚██╔╝██╗    ██║╚██╔╝██╗    ██╔══██║      ╚██╔╝  
╚██████╔╝   ██║  ██║    ██║ ╚═╝ ██║    ██║ ╚═╝ ██║    ██║  ██║       ██║   
 ╚═════╝    ╚═╝  ╚═╝    ╚═╝     ╚═╝    ╚═╝     ╚═╝    ╚═╝  ╚═╝       ╚═╝   
`,
	Run: func(cmd *cobra.Command, args []string) {
		if Fingerprint == true || Subdomaindetect == true || NormalLayerExploit == true {
			Tp.Scan, _ = task.NewTaskPool(Tp.Params.Thread, Tp.Params.Timeout)
			if Fingerprint == true {
				start := time.Now()
				logger.Info(logger.Global.Color().Green("Start running nmap scan task"))
				nmap.Nmapinit(Tp)
				Nconfig := NmapNew()

				Tp.Scan.Submit(nmap.Start(Tp, Nconfig))
				Tp.Scan.Wait()
				logger.Info(logger.Global.Color().Magenta("The nmap scan task has ended, taking - " + time.Since(start).String()))
			}
			if Subdomaindetect == true {
				start := time.Now()
				logger.Info(logger.Global.Color().Green("Start running subdomain enumeration scan task"))

				Tp.Scan.Submit(nmap.Subdomaindetect(nmap.SubdomainInit(Tp, MaxEnumerationTime), Tp.Params.Domain))
				Tp.Scan.Wait()
				logger.Info(logger.Global.Color().Magenta("The subdomain enumeration scan task has ended, taking - " + time.Since(start).String()))

			}
			if NormalLayerExploit == true {
				if len(Tp.Params.Domain) > 1 {
					logger.Fatal(logger.Global.Color().RedBg("Detect a single domain name each time"))
				}
				start := time.Now()
				logger.Info(logger.Global.Color().Green("Start running subdomain enumeration scan task"))
				LC := nmap.LayerConfigInit(Tp.Params, MaxLayerExploitTime, MatchStatus)
				scanner, _ := nmap.ScannerInit(Tp.Params, LC)
				fmt.Println(scanner)
				ctx, cancel := context.WithTimeout(context.Background(), LC.Timeout)
				pathChan := make(chan string, 1000)
				defer cancel()
				Tp.Scan.Submit(nmap.NormalLayermain(Tp.Params, ctx, pathChan, scanner))
				Tp.Scan.Submit(nmap.DelegateTask(suffix, pathChan, ctx))

				Tp.Scan.Wait()
				logger.Info(logger.Global.Color().Magenta("The subdomain enumeration scan task has ended, taking - " + time.Since(start).String()))
			}
		}

		if LayerExploit == true {
			start := time.Now()
			if len(Tp.Params.Domain) > 1 {
				logger.Fatal(logger.Global.Color().RedBg("Detect a single domain name each time"))
			}
			logger.Info(logger.Global.Color().Green("Start running background layer scan task"))
			LC := nmap.LayerConfigInit(Tp.Params, MaxLayerExploitTime, MatchStatus)
			nmap.Layermain(Tp.Params, LC)

			logger.Info(logger.Global.Color().Magenta("The background layer scan task has ended, taking - " + time.Since(start).String()))

		}

	},
}
var (
	Fingerprint         bool
	LayerExploit        bool
	NormalLayerExploit  bool
	MaxEnumerationTime  int
	Subdomaindetect     bool
	CDN                 bool
	ping                bool
	MaxLayerExploitTime int
	MatchStatus         []int
	suffix              []int
)

func init() {
	rootCmd.AddCommand(nmapCmd)
	nmapCmd.Flags().BoolVarP(&Fingerprint, "fp", "", false, "是否进行端口指纹探测")
	nmapCmd.Flags().BoolVarP(&CDN, "CDN", "", false, "对目标IP进行CDN扫描")
	nmapCmd.Flags().BoolVarP(&ping, "ping", "", false, "ping探测存活主机")
	nmapCmd.Flags().BoolVarP(&Subdomaindetect, "dd", "", false, "是否进行子域名探测")
	nmapCmd.Flags().IntVarP(&MaxEnumerationTime, "METime", "", 10, "设置最大枚举时间")
	nmapCmd.Flags().BoolVarP(&LayerExploit, "le", "", false, "是否进行后台爆破探测")
	nmapCmd.Flags().BoolVarP(&NormalLayerExploit, "nle", "", false, "是否进行普通后台爆破探测")
	nmapCmd.Flags().IntVarP(&MaxLayerExploitTime, "MLETime", "", 10, "设置最大爆破时间(default: 10 min)")
	nmapCmd.Flags().IntSliceVarP(&MatchStatus, "status", "", []int{200}, "设置匹配状态码")
	nmapCmd.Flags().IntSliceVarP(&suffix, "suffix", "", []int{1, 3}, "1.php 2.jsp 3.dir 4.aspx 5.mdb 6.asp")

}

func NmapNew() *DP.NmapConfig {
	return &DP.NmapConfig{
		Fingerprint:        Fingerprint,
		MaxEnumerationTime: MaxEnumerationTime,
		Subdomaindetect:    Subdomaindetect,
		CDN:                CDN,
		Ping:               ping,
		LayerExploit:       LayerExploit,
	}
}
