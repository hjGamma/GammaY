package task

import (
	"gammay/core/DP"
	"sync"
	"time"
	"github.com/panjf2000/ants/v2"
)

// Pool 任务池
type Pool struct {
	Pool    *ants.Pool     // 协程池
	Wg      *sync.WaitGroup // 阻塞器
	Timeout time.Duration   // 任务超时时间（可选）
}
type TaskPool struct {
	Scan   *Pool
	Params DP.ScanParams
}

