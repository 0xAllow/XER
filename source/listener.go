package main

import (
 "net"
 "sync"
)

type boundedListener struct{net.Listener;slots chan struct{}}
type countedConn struct{net.Conn;once sync.Once;release func()}
func(c *countedConn)Close()error{err:=c.Conn.Close();c.once.Do(c.release);return err}
func(l *boundedListener)Accept()(net.Conn,error){
 for {c,err:=l.Listener.Accept();if err!=nil{return nil,err}
  select{case l.slots<-struct{}{}:return &countedConn{Conn:c,release:func(){<-l.slots}},nil;default:c.Close()}
 }
}
