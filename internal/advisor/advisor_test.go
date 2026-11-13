package advisor
import ("os";"path/filepath";"reflect";"strings";"testing")
func TestDetectSortedAndMinimized(t *testing.T) {
 root:=t.TempDir()
 for _,name:=range []string{"AGENTS.md","CLAUDE.md","pyproject.toml","requirements.txt"} {
  if err:=os.WriteFile(filepath.Join(root,name),[]byte("SENSITIVE_CONTENT_DO_NOT_READ"),0600);err!=nil{t.Fatal(err)}
 }
 got,err:=Detect(root);if err!=nil{t.Fatal(err)}
 want:=[]Signal{{"Agent instructions",[]string{"AGENTS.md"}},{"Claude project instructions",[]string{"CLAUDE.md"}},{"Python project",[]string{"pyproject.toml","requirements.txt"}}}
 if !reflect.DeepEqual(got,want){t.Fatalf("signals=%+v",got)}
 for _,s:=range got {if strings.Contains(s.Name+strings.Join(s.Evidence,""),"SENSITIVE_CONTENT"){t.Fatal("leaked content")}}
 if !strings.Contains(strings.Join(Guidance(got)," "),"not proof"){t.Fatal("limitations omitted")}
}
func TestDetectDoesNotFollowSymlinks(t *testing.T) {
 root,outside:=t.TempDir(),t.TempDir()
 if err:=os.WriteFile(filepath.Join(outside,"AGENTS.md"),[]byte("secret"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(filepath.Join(outside,"AGENTS.md"),filepath.Join(root,"AGENTS.md"));err!=nil{t.Skip(err)}
 if err:=os.Symlink(outside,filepath.Join(root,".cursor"));err!=nil{t.Skip(err)}
 found,err:=Detect(root);if err!=nil{t.Fatal(err)}
 if len(found)!=0{t.Fatalf("symlink markers detected: %+v",found)}
}
func TestUnexpectedFileShapeIgnored(t *testing.T) {
 root:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(root,".github"),[]byte("not a directory"),0600);err!=nil{t.Fatal(err)}
 found,err:=Detect(root);if err!=nil{t.Fatal(err)}
 if len(found)!=0{t.Fatal(found)}
}
func TestEmptyGuidance(t *testing.T){
 if !strings.Contains(strings.Join(Guidance(nil)," "),"No known project indicators"){t.Fatal("missing explanation")}
}
