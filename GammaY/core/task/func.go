package task

import (
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

func NewTaskPool(Thread int, timeout time.Duration) (*Pool, error) {
	pool, err := ants.NewPool(Thread) // 创建协程池
	if err != nil {
		return nil, err
	}

	return &Pool{
		Pool:    pool,
		Wg:      &sync.WaitGroup{},
		Timeout: timeout,
	}, nil
}

func (tp *Pool) Submit(task func()) error {
	tp.Wg.Add(1) // 增加阻塞器计数

	// 将任务包装，确保任务完成后调用 Done
	wrappedTask := func() {
		defer tp.Wg.Done()
		task() // 执行用户任务
	}

	// 提交任务到协程池
	return tp.Pool.Submit(wrappedTask)
}

func (tp *Pool) Wait() {
	tp.Wg.Wait() // 阻塞直到所有任务完成
}

func (tp *Pool) Release() {
	tp.Pool.Release() // 释放协程池资源
}
