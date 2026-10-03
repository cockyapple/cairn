package logserver

func (s *Server) SetCrashHook(fn func(point string, height uint64)) { s.crashHook = fn }
