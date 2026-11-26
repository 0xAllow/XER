package main
import("context";"crypto/sha256";"encoding/hex";"errors";"io";"net/http";"time")
type networkIdleContextKey struct{}
type contextReader struct{ctx context.Context;reader io.Reader}
func(r contextReader)Read(b []byte)(int,error){if err:=r.ctx.Err();err!=nil{return 0,err};return r.reader.Read(b)}
func shaFileContext(ctx context.Context,path string)(string,error){
 f,err:=openPrivate(path,0);if err!=nil{return "",err};defer f.Close();h:=sha256.New()
 if _,err=io.Copy(h,contextReader{ctx,f});err!=nil{return "",err};return hex.EncodeToString(h.Sum(nil)),nil
}
// Full-file hashing can take longer than ordinary response-header timeouts.
// Use a separate, bounded completion connection, retaining identical TLS/proxy
// policy, rather than disabling all transfer timeouts.
func completeUpload(client *http.Client,token,endpoint string)error{
 transport,ok:=client.Transport.(*http.Transport);if !ok{return errors.New("unsupported completion transport")}
 clone:=transport.Clone();clone.ResponseHeaderTimeout=30*time.Minute;defer clone.CloseIdleConnections()
 completionClient:=&http.Client{Transport:clone,CheckRedirect:client.CheckRedirect}
 ctx,cancel:=context.WithTimeout(context.WithValue(context.Background(),networkIdleContextKey{},30*time.Minute),30*time.Minute);defer cancel()
 req,err:=http.NewRequestWithContext(ctx,"POST",endpoint,nil);if err!=nil{return err};req.Header.Set(headerToken,"Bearer "+token)
 resp,err:=completionClient.Do(req);if err!=nil{return err};defer resp.Body.Close();return checkStatus(resp,200)
}
