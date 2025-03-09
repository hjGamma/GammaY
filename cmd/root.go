package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/yqcs/fingerscan"

	"gammay/core/DP"
	"gammay/core/task"
	"gammay/utils/logger"
	"gammay/utils/parse"
)

var rootCmd = &cobra.Command{
	Use:   "gammay",
	Short: "gammay is a tool for gamma ray analysis",
	Long: `
 ██████╗    █████╗    ███╗   ███╗   ███╗   ███╗    █████╗   ██╗   ██╗
██╔════╝   ██╔══██╗   ████╗ ████╗   ████╗ ████╗   ██╔══██╗  ╚██╗ ██╔╝
██║  ███╗  ███████║   ██╔████╔██╗   ██╔████╔██╗   ███████║   ╚████╔╝ 
██║   ██║  ██╔══██║   ██║╚██╔╝██╗   ██║╚██╔╝██╗   ██╔══██║    ╚██╔╝  
╚██████╔╝  ██║  ██║   ██║ ╚═╝ ██║   ██║ ╚═╝ ██║   ██║  ██║     ██║   
 ╚═════╝   ╚═╝  ╚═╝   ╚═╝     ╚═╝   ╚═╝     ╚═╝   ╚═╝  ╚═╝     ╚═╝         `,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		fmt.Println(cmd.Long)
		hosts, domain, err := parse.ParseIP(TargetIP)
		var params DP.ScanParams
		if err != nil {
			logger.Fatal(err)
		}
		params = DP.ScanParams{
			IP:     hosts,
			Domain: domain,
			Port:   Port,
			Mode:   Mode,
		}
		//控制协程数量
		if Mode == "s" {
			params.Thread = 800
			params.Timeout = 20 * time.Second
		}

		if Mode == "d" {
			params.Thread = 1500
			params.Timeout = 15 * time.Second
		}

		if Mode == "f" {
			params.Thread = 2500
			params.Timeout = 15 * time.Second
		}
		p, err := task.NewTaskPool(params.Thread, params.Timeout)
		if err != nil {
			logger.Fatal(err)
		}
		Tp = &task.TaskPool{
			Scan:   p,
			Params: params,
		}

		defer Tp.Scan.Release()

	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var (
	TargetIP        []string
	Port            []int
	Mode, BlackPort string

	Tp *task.TaskPool
)

func init() {
	fingerscan.InitFinger()
	rootCmd.PersistentFlags().StringSliceVarP(&TargetIP, "ip", "t", TargetIP, "Target ip")
	rootCmd.PersistentFlags().IntSliceVarP(&Port, "port", "p", Port, "Target port")
	rootCmd.PersistentFlags().StringVarP(&BlackPort, "BlackPort", "", "", "Setting up a port to disable access")
	rootCmd.PersistentFlags().StringVarP(&Mode, "mode", "m", "s", "Setting the thread size ")
	rootCmd.MarkFlagRequired("TargetIP")

	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(TargetIP) == 0 {
			logger.Warn("Run command: -h")
			os.Exit(1)
		}
	}
}
func Start() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
