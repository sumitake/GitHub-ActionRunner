"""The release metadata must identify the package snapshot actually built."""
import ast,json,pathlib,re,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
def rehearsal():
 p=ROOT/'scripts/release/rehearse-runtime.sh';s=p.read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0];t=ast.parse(s);t.body=t.body[:-1];n={};exec(compile(t,str(p),'exec'),n);return n
class RuntimeSnapshotBinding(unittest.TestCase):
 def test_manifest_matches_real_runner_dockerfile(self):
  m=json.loads((ROOT/'release/manifest.json').read_text())['runtime'];d=(ROOT/'images/runner/Dockerfile').read_text();self.assertEqual(re.findall(r'\bsnapshot=([0-9]{8}T[0-9]{6}Z);',d),[m['debian_snapshot']])
 def test_drift_is_rejected_before_build(self):
  n=rehearsal();m=json.loads((ROOT/'release/manifest.json').read_text())['runtime'];m['images']=[{'name':'runner','dockerfile':'Dockerfile'}]
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);content=(ROOT/'images/runner/Dockerfile').read_text();content=re.sub(r'\bsnapshot=[0-9]{8}T[0-9]{6}Z;', 'snapshot=20200101T000000Z;',content);(root/'Dockerfile').write_text(content)
   with self.assertRaises(n['RehearsalError']):n['validate_dockerfiles'](root,m)
if __name__=='__main__':unittest.main()
