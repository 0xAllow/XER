package main
import("os";"path/filepath";"strings";"testing";"time")
func TestAutomationValidationAndAbsoluteSource(t *testing.T){
 isolateUserState(t)
 bad:=[]byte("name: bad\nfrom: file\nto: localhost\nvia: ftp\nevery: manual\n")
 if _,e:=parseJob(bad);e==nil{t.Fatal("unsupported protocol accepted")}
 dir:=t.TempDir();input:=filepath.Join(dir,"job.yaml")
 if e:=os.WriteFile(input,[]byte("name: job\nfrom: data.bin\nto: localhost\nvia: https\nevery: manual\n"),0600);e!=nil{t.Fatal(e)}
 if e:=automation([]string{"add",input});e!=nil{t.Fatal(e)}
 job,e:=loadJob("job");if e!=nil{t.Fatal(e)}
 if job.From!=filepath.Join(dir,"data.bin"){t.Fatal("job source is not anchored to job location",job.From)}
 if e=automation([]string{"add",input});e==nil{t.Fatal("job overwrite accepted")}
}
func TestTickReportsEachFailedJob(t *testing.T){
 isolateUserState(t);dir,e:=jobFolder();if e!=nil{t.Fatal(e)};if e=privateDir(dir);e!=nil{t.Fatal(e)}
 now:=time.Date(2026,11,25,12,0,0,0,time.UTC)
 for _,name:=range []string{"first","second"}{data:="name: "+name+"\nfrom: /nonexistent/disposable-file\nto: localhost\nvia: https\nevery: hourly\n";if e=writeExclusive(filepath.Join(dir,name+".yaml"),[]byte(data));e!=nil{t.Fatal(e)}}
 e=runDueJobs(dir,now)
 if e==nil || !strings.Contains(e.Error(),"first") || !strings.Contains(e.Error(),"second"){t.Fatal("one failed job prevented another from being checked",e)}
 for _,name:=range []string{"first","second"}{if _,e=os.Stat(filepath.Join(dir,name+".last.json"));!os.IsNotExist(e){t.Fatal("failed job was recorded as success",e)}}
}
func TestKernelLockAndJSONValidation(t *testing.T){
 path:=filepath.Join(t.TempDir(),"state.lock");one,e:=acquireLock(path);if e!=nil{t.Fatal(e)}
 if two,e:=acquireLock(path);e==nil{two.Close();one.Close();t.Fatal("same lock was acquired twice")}
 if e=one.Close();e!=nil{t.Fatal(e)};two,e:=acquireLock(path);if e!=nil{t.Fatal("released lock was not recoverable",e)};two.Close()
}

func TestQuotedYAMLPathsAreLiteral(t *testing.T){
 j,e:=parseJob([]byte("name: job\nfrom: '/tmp/O''Neil #1 & [2].bin'\nto: '[::1]:8443'\nvia: https\nevery: manual\n"))
 if e!=nil || j.From!="/tmp/O'Neil #1 & [2].bin" || j.To!="[::1]:8443"{t.Fatal("quoted literal changed",j,e)}
}
