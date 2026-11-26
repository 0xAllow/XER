package main
import("net";"sync";"time")
// Idle deadlines cap a stalled peer while permitting a long transfer that keeps
// making progress. Explicit shorter proxy/handshake deadlines remain effective.
type idleConn struct{net.Conn;mu sync.Mutex;readAt,writeAt time.Time;idle time.Duration}
func(c *idleConn)limit(explicit time.Time)time.Time{t:=time.Now().Add(c.idle);if !explicit.IsZero() && explicit.Before(t){return explicit};return t}
func(c *idleConn)Read(b []byte)(int,error){c.mu.Lock();err:=c.Conn.SetReadDeadline(c.limit(c.readAt));c.mu.Unlock();if err!=nil{return 0,err};return c.Conn.Read(b)}
func(c *idleConn)Write(b []byte)(int,error){c.mu.Lock();err:=c.Conn.SetWriteDeadline(c.limit(c.writeAt));c.mu.Unlock();if err!=nil{return 0,err};return c.Conn.Write(b)}
func(c *idleConn)SetDeadline(t time.Time)error{c.mu.Lock();defer c.mu.Unlock();c.readAt=t;c.writeAt=t;return c.Conn.SetDeadline(t)}
func(c *idleConn)SetReadDeadline(t time.Time)error{c.mu.Lock();defer c.mu.Unlock();c.readAt=t;return c.Conn.SetReadDeadline(t)}
func(c *idleConn)SetWriteDeadline(t time.Time)error{c.mu.Lock();defer c.mu.Unlock();c.writeAt=t;return c.Conn.SetWriteDeadline(t)}
func(c *idleConn)CloseWrite()error{if cw,ok:=c.Conn.(interface{CloseWrite()error});ok{return cw.CloseWrite()};return c.Conn.Close()}
