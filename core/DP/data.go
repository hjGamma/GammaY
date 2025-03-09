package DP

import (
	"time"
)

type ScanParams struct {
	IP, Domain      []string
	Port            []int
	Mode, BlackPort string        //要检查的IP、端口以及黑名单
	Timeout         time.Duration //网络超时
	Thread          int           //线程数
}

type NmapConfig struct {
	MaxEnumerationTime int
	Subdomaindetect   bool
	CDN     bool
	Ping    bool
	Fingerprint bool
}

type vulnerability struct {
	IP, Port, VulnName, VulnType, VulnUrl, VulnPayload, VulnDetail string
}

type subdomain struct {
	Domain string
}
