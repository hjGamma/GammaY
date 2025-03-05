package DP

import (
	"time"
)

type ScanParams struct {
	IP, Domain []string
	Port, Mode string        //要检查的IP、端口以及黑名单
	Timeout    time.Duration //网络超时
	Thread     int           //线程数
}

type vulnerability struct {
	IP, Port, VulnName, VulnType, VulnUrl, VulnPayload, VulnDetail string
}

type subdomain struct {
	Domain string
}

type fingerprint struct {
	IP, Port, Banner string
}
