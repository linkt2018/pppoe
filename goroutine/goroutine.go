package goroutine

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"runtime"
	"sync"
)

// GlobalWg 全局 WaitGroup
// 用于监控全局的协程，保证所有协程退出后再退出进程。
// 注意：此 Wait Group 的 Wait 设计为在进程要退出时在 main 函数中调用。若在此协程内调用会造成死锁。
var GlobalWg = sync.WaitGroup{}

var goroutineCount = make(chan struct{}, 50)

func Go(f func()) {
	go func() {
		GlobalWg.Add(1)
		goroutineCount <- struct{}{}

		defer func() {
			GlobalWg.Done()
			<-goroutineCount
			if r := recover(); r != nil {
				logrus.Errorln("recover", r, fmt.Sprintf("%+v", callers()))
			}
		}()

		f()
	}()
}

type stack []uintptr

func callers() *stack {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	var st stack = pcs[0:n]
	return &st
}

func (s *stack) Format(st fmt.State, verb rune) {
	switch verb {
	case 'v':
		switch {
		case st.Flag('+'):
			for _, pc := range *s {
				f := errors.Frame(pc)
				_, _ = fmt.Fprintf(st, "\n%+v", f)
			}
		}
	}
}
