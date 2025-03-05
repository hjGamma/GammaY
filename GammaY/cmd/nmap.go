package cmd

import (
	"fmt"
	"gammay/core/DP"
	"gammay/core/task"
	"gammay/utils/logger"
	"github.com/spf13/cobra"
)

var nmapCmd = &cobra.Command{
	Use: "nmap",
	Long: `
 ██████╗     █████╗     ███╗   ███╗    ███╗   ███╗     █████╗     ██╗   ██╗
██╔════╝    ██╔══██╗    ████╗ ████╗    ████╗ ████╗    ██╔══██╗    ╚██╗ ██╔╝
██║  ███╗   ███████║    ██╔████╔██╗NMAP██╔████╔██╗    ███████║     ╚████╔╝ 
██║   ██║   ██╔══██║    ██║╚██╔╝██╗    ██║╚██╔╝██╗    ██╔══██║      ╚██╔╝  
╚██████╔╝   ██║  ██║    ██║ ╚═╝ ██║    ██║ ╚═╝ ██║    ██║  ██║       ██║   
 ╚═════╝    ╚═╝  ╚═╝    ╚═╝     ╚═╝    ╚═╝     ╚═╝    ╚═╝  ╚═╝       ╚═╝   
`,
	Run: func(cmd *cobra.Command, args []string) {
		
		
	},
}
var (
	Ping bool
	TCP  bool
	ICMP bool
	UDP  bool
)

func init() {
	rootCmd.AddCommand(nmapCmd)
	nmapCmd.Flags().BoolVarP(&Ping, "Ping", "P", false, "对目标IP进行PING扫描")
	nmapCmd.Flags().BoolVarP(&TCP, "TCP", "T", false, "对目标IP进行TCP扫描")
	nmapCmd.Flags().BoolVarP(&ICMP, "ICMP", "I", false, "对目标IP进行ICMP扫描")
	nmapCmd.Flags().BoolVarP(&UDP, "UDP", "U", false, "对目标IP进行UDP扫描")

}
