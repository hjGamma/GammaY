package parse

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

const ipv4Regex = `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`

const ipv6Regex = `^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`

const domainRegex = `([a-zA-Z0-9-]+|\p{Han})+\.[a-zA-Z\p{Han}]+`

var (
	ipv4Reg   = regexp.MustCompile(ipv4Regex)
	ipv6Reg   = regexp.MustCompile(ipv6Regex)
	domainReg = regexp.MustCompile(domainRegex)
)

func ParseIP(Target []string) ([]string, []string, error) {
	var (
		ipSet     = make(map[string]struct{})
		domainSet = make(map[string]struct{})
		invalid   []string
		mu        sync.Mutex
	)

	for _, raw := range Target {
		// 分离主机和端口
		host, _, err := net.SplitHostPort(raw)
		if err != nil {
			host = raw // 无端口时直接使用
		}

		// 执行验证
		isIP, standardized, valid := ValidateTarget(host)
		if !valid {
			mu.Lock()
			invalid = append(invalid, raw)
			mu.Unlock()
			continue
		}

		// 分类存储
		mu.Lock()
		if isIP {
			ipSet[standardized] = struct{}{}
		} else {
			domainSet[standardized] = struct{}{}
		}
		mu.Unlock()
	}
	fmt.Println("invalid:", invalid)
	return mapKeysToSlice(ipSet), mapKeysToSlice(domainSet), nil
}

func ValidateTarget(host string) (isIP bool, standardized string, valid bool) {
	// 预处理：去除前后空白、转换为小写
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)

	// 尝试解析为IP
	if ip := net.ParseIP(host); ip != nil {
		return true, ip.String(), true
	}

	// 处理国际化域名（IDN）
	asciiDomain, err := idna.New().ToASCII(host)
	if err != nil {
		return false, "", false
	}

	// 验证域名格式
	if domainReg.MatchString(asciiDomain) {
		return false, asciiDomain, true
	}

	// 验证IPv4/IPv6字符串（非net.ParseIP能解析的格式）
	if ipv4Reg.MatchString(host) || ipv6Reg.MatchString(host) {
		return true, host, true
	}

	return false, "", false
}

func mapKeysToSlice(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
