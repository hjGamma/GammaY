package cmd

//待添加功能
// 1.域名转换IP进行端口指纹探测以及bypassCDN
// 2.C段探测，根据提交的掩码进行C段探测
import (
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

			Tp.Scan.Submit(nmap.Subdomaindetect(nmap.SubdomainInit(Tp),MaxEnumerationTime))
			Tp.Scan.Wait()
			logger.Info(logger.Global.Color().Magenta("The subdomain enumeration scan task has ended, taking - " + time.Since(start).String()))

		}

	},
}
var (
	Fingerprint        bool
	MaxEnumerationTime int
	Subdomaindetect    bool
	CDN                bool
	ping               bool
)

func init() {
	rootCmd.AddCommand(nmapCmd)
	nmapCmd.Flags().BoolVarP(&Fingerprint, "fp", "", false, "是否进行端口指纹探测")
	nmapCmd.Flags().BoolVarP(&CDN, "CDN", "", false, "对目标IP进行CDN扫描")
	nmapCmd.Flags().BoolVarP(&ping, "ping", "", false, "ping探测存活主机")
	nmapCmd.Flags().BoolVarP(&Subdomaindetect, "dd", "", false, "是否进行子域名探测")
	nmapCmd.Flags().IntVarP(&MaxEnumerationTime, "METime", "", 10, "设置最大枚举时间")

}

func NmapNew() *DP.NmapConfig {
	return &DP.NmapConfig{
		Fingerprint:        Fingerprint,
		MaxEnumerationTime: MaxEnumerationTime,
		Subdomaindetect:    Subdomaindetect,
		CDN:                CDN,
		Ping:               ping,
	}
}
