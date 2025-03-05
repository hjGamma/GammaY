package cmd

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/spf13/cobra"

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
 ╚═════╝   ╚═╝  ╚═╝   ╚═╝     ╚═╝   ╚═╝     ╚═╝   ╚═╝  ╚═╝     ╚═╝   `,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		fmt.Println(cmd.Long)
		hosts, domain, err := parse.ParseIP(TargetIP)

		if err != nil {
			logger.Fatal(err)
		}
		params = DP.ScanParams{
			IP:     hosts,
			Domain: domain,
			Port:   Port,
			Mode:   mode,
		}

		if mode == "s" {
			params.Thread = 800
			params.Timeout = 20 * time.Second
		}

		if mode == "d" {
			params.Thread = 1500
			params.Timeout = 15 * time.Second
		}

		if mode == "f" {
			params.Thread = 2500
			params.Timeout = 15 * time.Second
		}
		tp:=task.NewTaskPool(params.Thread, params.Timeout)


	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var (
	TargetIP []string
	Port     string
	mode     string
	params   DP.ScanParams
)

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&TargetIP, "ip", "t", TargetIP, "Target ip")
	rootCmd.Flags().StringVarP(&Port, "port", "p", "80", "Target port")
	rootCmd.Flags().StringVarP(&mode, "mode", "m", "s", "mode")
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
