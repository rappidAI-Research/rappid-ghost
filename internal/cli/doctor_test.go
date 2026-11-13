package cli

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/rappidAI-research/rappid-ghost/internal/config"
)

func TestDoctorFlagsStrict(t *testing.T) {
 for _,tc:=range []struct{args []string; json,valid bool}{
  {nil,false,true},
  {[]string{"--json"},true,true},
  {[]string{"--json","extra"},false,false},
  {[]string{"--repair"},false,false},
 }{
  got,err:=parseDoctorArgs(tc.args)
  if (err==nil)!=tc.valid || (err==nil&&got!=tc.json){t.Fatalf("args=%v got=%v err=%v",tc.args,got,err)}
 }
}

func TestDoctorIsAdvisoryAndDoesNotReadProjectContents(t *testing.T){
 root:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(root,"package.json"),[]byte("DO_NOT_READ_SECRET"),0600);err!=nil{t.Fatal(err)}
 report,err:=buildDoctorReport(root,"unreachable");if err!=nil{t.Fatal(err)}
 if report.Configuration!="missing" || report.RuntimeValidated || report.Docker!="unreachable"{t.Fatalf("report=%+v",report)}
 if _,err:=os.Lstat(filepath.Join(root,config.FileName));!os.IsNotExist(err){t.Fatal("doctor created config")}
 b,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
 if bytes.Contains(b,[]byte("DO_NOT_READ_SECRET")){t.Fatal("leaked project content")}
 if !strings.Contains(string(b),"does not include"){t.Fatal("missing runtime compatibility warning")}
}

func TestDoctorExplainsPolicyWithoutWeakeningIt(t *testing.T){
 root:=t.TempDir()
 if _,err:=config.WriteDefault(filepath.Join(root,config.FileName));err!=nil{t.Fatal(err)}
 before,err:=os.ReadFile(filepath.Join(root,config.FileName));if err!=nil{t.Fatal(err)}
 report,err:=buildDoctorReport(root,"reachable");if err!=nil{t.Fatal(err)}
 if report.Configuration!="valid" || report.Policy==nil || report.Policy.Network!="deny" || report.RuntimeValidated{t.Fatalf("policy=%+v",report)}
 after,err:=os.ReadFile(filepath.Join(root,config.FileName));if err!=nil{t.Fatal(err)}
 if !bytes.Equal(before,after){t.Fatal("doctor changed the policy")}
}

func TestDoctorDoesNotFixInvalidConfig(t *testing.T){
 root:=t.TempDir();path:=filepath.Join(root,config.FileName)
 if err:=os.WriteFile(path,[]byte("version: 100\n"),0600);err!=nil{t.Fatal(err)}
 report,err:=buildDoctorReport(root,"missing")
 if err!=nil || report.Configuration!="invalid" || report.Policy!=nil {t.Fatalf("report=%+v err=%v",report,err)}
 b,err:=os.ReadFile(path);if err!=nil||string(b)!="version: 100\n"{t.Fatal("invalid config overwritten")}
}
