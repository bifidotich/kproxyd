package main

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// rotLog — журнал в файле с ротацией на ходу: когда файл перерастает max, он переименовывается
// в .1 (прежний .1 затирается) и открывается заново, так что на диске не больше ~2×max.
// Stdout и stderr процесса перенаправляются в текущий файл, чтобы туда же попадали паники рантайма.
// Write вызывается из log.Logger под его блокировкой, поэтому своя не нужна.
type rotLog struct {
	path string
	max  int64
	f    *os.File
	size int64
}

func openRotLog(path string, max int64) (*rotLog, error) {
	l := &rotLog{path: path, max: max}
	if err := l.open(); err != nil {
		return nil, err
	}
	if l.size > max {
		l.rotate()
	}
	return l, nil
}

func (l *rotLog) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	_ = syscall.Dup3(int(f.Fd()), 1, 0)
	_ = syscall.Dup3(int(f.Fd()), 2, 0)
	if l.f != nil {
		l.f.Close()
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *rotLog) rotate() {
	err := os.Rename(l.path, l.path+".1")
	// ErrNotExist: прошлый раз файл перенесли, а новый не открылся (или журнал удалили руками)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		if l.open() == nil {
			return
		}
	}
	// ни перенести, ни открыть новый не вышло — обрезаем текущий: журнал не должен расти без границ
	if l.f.Truncate(0) == nil {
		l.size = 0
	}
}

func (l *rotLog) Write(p []byte) (int, error) {
	n, err := l.f.Write(p)
	l.size += int64(n)
	if l.size > l.max {
		l.rotate()
	}
	return n, err
}
