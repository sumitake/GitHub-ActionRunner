"""Synthetic archive identity checks for the optional runtime rebuild."""
import ast,copy,hashlib,json,os,pathlib,tempfile,unittest
from tests.repository.test_runtime_snapshot_binding import rehearsal

class RunnerRebuild(unittest.TestCase):
    def setUp(self):
        self.n=rehearsal();self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.descriptor=self.root/'internal/buildinfo/runner_rebuild.json';self.descriptor.parent.mkdir(parents=True)
        self.patch=self.root/'release/runner-rebuild.patch';self.patch.parent.mkdir();self.patch.write_bytes(b'synthetic source patch\n')
        self.runner={'version':'v1.2.3','source_commit_sha':'c'*40,'linux_x64_asset_digest':'sha256:'+'a'*64,'linux_x64_asset_name':'actions-runner-linux-x64-1.2.3.tar.gz','linux_x64_asset_size':12}
        self.d={'schema_version':1,'enabled':True,'upstream_version':'v1.2.3','upstream_source_commit':'c'*40,'upstream_linux_x64_sha256':'a'*64,'dotnet_sdk_version':'8.0.426','dotnet_runtime_version':'8.0.32','sdk_container_image':'mcr.microsoft.com/dotnet/sdk@sha256:'+'e'*64,'sdk_archive_sha512':'d'*128,'source_patch_sha256':hashlib.sha256(self.patch.read_bytes()).hexdigest(),'asset_name':'actions-runner-linux-x64-1.2.3-dotnet-8.0.32.tar.gz','linux_x64_sha256':hashlib.sha256(b'fixture').hexdigest(),'archive_bytes':7}
    def write(self,d=None):
        self.descriptor.write_text(json.dumps(self.d if d is None else d,indent=2)+'\n')
    def select(self):return self.n['select_runner_payload'](self.root,self.runner)
    def test_rebuild_keeps_official_identity_separate(self):
        self.write();before=copy.deepcopy(self.runner);payload=self.select();self.assertEqual(self.runner,before);self.assertEqual(payload['kind'],'dotnet-rebuild');self.assertEqual(payload['sha256'],self.d['linux_x64_sha256']);self.assertEqual(payload['provenance_sha256'],hashlib.sha256(self.descriptor.read_bytes()).hexdigest())
    def test_actual_sdk_container_input_is_bound_and_immutable(self):
        self.d['sdk_container_image'] = 'mcr.microsoft.com/dotnet/sdk@sha256:' + 'e' * 64
        ordered = {}
        for key, value in self.d.items():
            if key == 'sdk_archive_sha512':
                ordered['sdk_container_image'] = self.d['sdk_container_image']
            if key != 'sdk_container_image':
                ordered[key] = value
        self.d = ordered
        self.write()
        self.assertEqual(self.select()['kind'], 'dotnet-rebuild')
        for value in ('mcr.microsoft.com/dotnet/sdk:8.0.426', 'example.invalid/sdk@sha256:' + 'e' * 64):
            self.d['sdk_container_image'] = value
            self.write()
            with self.assertRaises(self.n['RehearsalError']):
                self.select()

    def test_source_patch_drift_is_refused(self):
        self.write();self.patch.write_bytes(b'changed source patch')
        with self.assertRaises(self.n['RehearsalError']):self.select()
    def test_disabled_and_new_official_candidate(self):
        self.write({'schema_version':1,'enabled':False});self.assertEqual(self.select()['kind'],'official')
        self.write();self.runner.update(version='v1.2.4',linux_x64_asset_digest='sha256:'+'f'*64,linux_x64_asset_name='actions-runner-linux-x64-1.2.4.tar.gz');self.assertEqual(self.select()['kind'],'official');self.assertEqual(self.select()['asset_name'],self.runner['linux_x64_asset_name'])
    def test_malformed_or_ambiguous_descriptor_is_refused(self):
        for field,value in [('unknown',True),('enabled',1),('dotnet_runtime_version','8.0.31'),('dotnet_sdk_version','8.0.425'),('archive_bytes',True),('archive_bytes',0),('asset_name','../escape.tar.gz'),('sdk_archive_sha512','bad'),('upstream_linux_x64_sha256','bad'),('source_patch_sha256','bad'),('upstream_version','v1.2.4'),('upstream_source_commit','f'*40)]:
            with self.subTest(field=field,value=value):
                d=copy.deepcopy(self.d);d[field]=value;self.write(d)
                with self.assertRaises(self.n['RehearsalError']):self.select()
        self.write();self.descriptor.write_text(self.descriptor.read_text().replace('{','{"enabled":false,',1))
        with self.assertRaises(self.n['RehearsalError']):self.select()
    def test_archive_parent_alias_is_refused(self):
        self.write();payload=self.select();archive=self.root/payload['asset_name'];archive.write_bytes(b'fixture');alias=self.root/'alias-parent';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(self.n['RehearsalError']):self.n['copy_rebuilt_runner_archive'](alias/archive.name,self.root/'output.tar.gz',payload)
    def test_local_archive_copy_requires_plain_exact_bytes(self):
        self.write();payload=self.select();archive=self.root/payload['asset_name'];archive.write_bytes(b'fixture');dest=self.root/'copied.tar.gz'
        self.n['copy_rebuilt_runner_archive'](archive,dest,payload);self.assertEqual(dest.read_bytes(),b'fixture');dest.unlink()
        archive.write_bytes(b'changed')
        with self.assertRaises(self.n['RehearsalError']):self.n['copy_rebuilt_runner_archive'](archive,dest,payload)
        self.assertFalse(dest.exists());archive.write_bytes(b'fixture');link=self.root/'alias';link.symlink_to(archive)
        with self.assertRaises(self.n['RehearsalError']):self.n['copy_rebuilt_runner_archive'](link,dest,payload)

class PublishedPayloadIdentity(unittest.TestCase):
    def test_published_metadata_refuses_descriptor_or_archive_substitution(self):
        fixture=RunnerRebuild();fixture.setUp();self.addCleanup(fixture.doCleanups);fixture.write();payload=fixture.select()
        path=pathlib.Path(__file__).resolve().parents[2]/"scripts/release/compare-runtime-rebuilds.sh"
        source=path.read_text().split("<<'PY'\n",1)[1].rsplit("\nPY\n",1)[0];tree=ast.parse(source);tree.body=tree.body[:-1];namespace={};exec(compile(tree,str(path),"exec"),namespace)
        (fixture.root/'runner-payload.json').write_bytes(namespace['canonical_json'](payload));(fixture.root/'runner-rebuild.json').write_bytes(fixture.descriptor.read_bytes())
        subjects={'runner-payload.json':{'type':'runner-payload'},'runner-rebuild.json':{'type':'runner-rebuild-provenance'}}
        namespace['validate_payload_subjects'](fixture.root,fixture.runner,subjects)
        payload['sha256']='f'*64;(fixture.root/'runner-payload.json').write_bytes(namespace['canonical_json'](payload))
        with self.assertRaises(namespace['ValidationError']):namespace['validate_payload_subjects'](fixture.root,fixture.runner,subjects)
        (fixture.root/'runner-payload.json').write_bytes(namespace['canonical_json'](fixture.select()));(fixture.root/'runner-rebuild.json').write_text('{}\n')
        with self.assertRaises(namespace['ValidationError']):namespace['validate_payload_subjects'](fixture.root,fixture.runner,subjects)

class PayloadTextAuthorities(unittest.TestCase):
    def test_selected_payload_metadata_is_always_scanned(self):
        namespace = rehearsal()
        stage = pathlib.Path('/synthetic/release')
        select = namespace['runner_payload_text_authorities']
        self.assertEqual(select(stage, {'kind': 'official'}), [stage / 'runner-payload.json'])
        self.assertEqual(select(stage, {'kind': 'dotnet-rebuild'}), [stage / 'runner-payload.json', stage / 'runner-rebuild.json'])

    def test_unknown_payload_kind_cannot_omit_metadata_scanning(self):
        namespace = rehearsal()
        with self.assertRaises(namespace['RehearsalError']):
            namespace['runner_payload_text_authorities'](pathlib.Path('/synthetic/release'), {'kind': 'unknown'})
