"""Candidate refresh cannot impersonate exact-original reconstruction."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/release'))
import _candidate_refresh as candidate
import _bounded_qualification as q
import _payload_reconstruction as original

class CandidateRefresh(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.source=self.root/'source';self.source.mkdir()
        self.environment=dict(GITHUB_EVENT_NAME='workflow_dispatch',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Linux',RUNNER_ARCH='X64',GITHUB_REPOSITORY='sumitake/GitHub-ActionRunner',GITHUB_ACTOR='sumitake',GITHUB_REF=candidate.BRANCH,GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',GITHUB_WORKSPACE=str(self.source))
        self.event={'repository':{'private':False,'full_name':'sumitake/GitHub-ActionRunner','owner':{'login':'sumitake'}},'inputs':{'candidate_refresh':'true','bounded_qualification':'false','metadata_probe':'false','payload_reconstruction':'false','expected_commit':'a'*40,'expected_tree':'b'*40,'carry_in_bytes':str(q.RESERVE)}}
        for f in ['internal/buildinfo/runner_rebuild.json','release/runner-rebuild.patch','internal/productionruntime/release_artifacts.go','scripts/release/rehearse-runtime.sh']:
            p=self.source/f;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/f).read_bytes())
        base=(ROOT/'release/runner-rebuild.patch').read_bytes()
        combined=base if hashlib.sha256(base).hexdigest()==candidate.COMBINED_PATCH_SHA256 else base+(ROOT/'release/runner-version-smoke.patch').read_bytes()
        (self.source/'release/runner-rebuild.patch').write_bytes(combined)
        self.descriptor=json.loads((ROOT/'internal/buildinfo/runner_rebuild.json').read_text());self.descriptor.update(source_patch_sha256=candidate.COMBINED_PATCH_SHA256,linux_x64_sha256='c'*64,archive_bytes=123)
        self.write_descriptor()
    def write_descriptor(self):
        (self.source/'internal/buildinfo/runner_rebuild.json').write_text(json.dumps(self.descriptor))
    def command(self,args,**kwargs):
        if 'ls-tree' in args:return ''
        if args[-2:]==['--format=%ct','HEAD']:return '123'
        if args[-1]=='HEAD':return 'a'*40
        if args[-1]=='HEAD^{tree}':return 'b'*40
        if args[-2:]==['--format=%ct','HEAD']:return '123'
        return ''
    def admit(self,event=None,environment=None):
        return candidate.admission(self.source,event or self.event,environment or self.environment,self.command)
    def test_admits_only_new_exact_source_and_real_adopted_sdk(self):
        value=self.admit();self.assertTrue(value['candidate_refresh']);self.assertEqual(value['sdk_sha256'],'c'*64);self.assertEqual(value['commit'],'a'*40);self.assertFalse(value['qualification_executed']);self.assertFalse(value['live_operations'])
    def test_rejects_wrong_actor_event_architecture_attempt_branch_and_source(self):
        for k,v in [('GITHUB_EVENT_NAME','push'),('RUNNER_ENVIRONMENT','self-hosted'),('RUNNER_ARCH','ARM64'),('GITHUB_ACTOR','other'),('GITHUB_REF',original.BRANCH),('GITHUB_SHA','d'*40),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_WORKSPACE','/tmp')]:
            with self.subTest(key=k),self.assertRaises(q.Stop):self.admit(environment={**self.environment,k:v})
    def test_rejects_mixed_unknown_and_unbounded_inputs(self):
        for k,v in [('candidate_refresh','false'),('payload_reconstruction','true'),('metadata_probe','true'),('bounded_qualification','true'),('unknown','true'),('carry_in_bytes','0'),('carry_in_bytes',str(q.SOFT)),('expected_tree','../invalid')]:
            e=copy.deepcopy(self.event);e['inputs'][k]=v
            with self.subTest(key=k),self.assertRaises(q.Stop):self.admit(event=e)
    def test_old_sdk_and_changed_compiler_or_source_patch_cannot_enter_new_mode(self):
        for key,value in [('linux_x64_sha256',candidate.OLD_SDK_SHA256),('dotnet_sdk_version','10.0.402'),('dotnet_runtime_version','10.0.13'),('upstream_source_commit','d'*40),('sdk_container_image','unbound'),('source_patch_sha256','d'*64),('enabled',False),('archive_bytes',True),('archive_bytes',2**30)]:
            before=copy.deepcopy(self.descriptor);self.descriptor[key]=value;self.write_descriptor()
            with self.subTest(key=key),self.assertRaises(q.Stop):candidate.sdk_authority(self.source)
            self.descriptor=before;self.write_descriptor()
        (self.source/'release/runner-rebuild.patch').write_bytes(b'drift')
        with self.assertRaises(q.Stop):candidate.sdk_authority(self.source)
    def test_changed_reviewed_smoke_code_is_not_silently_admitted(self):
        for f in ['internal/productionruntime/release_artifacts.go','scripts/release/rehearse-runtime.sh']:
            p=self.source/f;b=p.read_bytes();p.write_bytes(b+b'\n')
            with self.subTest(path=f),self.assertRaises(q.Stop):candidate.sdk_authority(self.source)
            p.write_bytes(b)
    def test_new_mode_does_not_enter_old_worker_profiles(self):
        worker=object.__new__(q.Qualification)
        for flag in ('reconstruction','go_patch_refresh'):
            with self.subTest(flag=flag),self.assertRaises(q.Stop):worker.build(candidate_refresh=True,**{flag:True})
    def test_final_smoke_receipt_must_include_both_real_paths_and_cleanup(self):
        graph={k:'sha256:'+'d'*64 for k in ('index_digest','manifest_digest','config_digest')}
        good={**graph,'schema_version':1,'image_id':'sha256:'+'d'*64,'runner_version':'2.338.0','production_smoke':True,'rehearsal_smoke':True,'stdout_sha256':hashlib.sha256(b'2.338.0\n').hexdigest(),'stderr_sha256':hashlib.sha256(b'').hexdigest(),'exit_code':0,'containers_removed':True,'image_removed':True}
        candidate.validate_smoke(good,graph,'2.338.0')
        for k,v in [('image_id','sha256:'+'e'*64),('runner_version','wrong'),('production_smoke',False),('rehearsal_smoke',False),('stdout_sha256','e'*64),('stderr_sha256','e'*64),('exit_code',1),('containers_removed',False),('image_removed',False),('extra',False)]:
            with self.subTest(key=k),self.assertRaises(q.Stop):candidate.validate_smoke({**good,k:v},graph,'2.338.0')
    def test_legacy_modes_only_ignore_explicit_false_new_selector(self):
        spec=importlib.util.spec_from_file_location('candidate_host',ROOT/'scripts/release/qualify-runtime.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
        old=copy.deepcopy(self.event);old['inputs']['candidate_refresh']='false';normalized=host.legacy_event(old)
        self.assertNotIn('candidate_refresh',normalized['inputs']);self.assertIn('candidate_refresh',old['inputs'])
        for value in ('true',False,None):
            bad=copy.deepcopy(old);bad['inputs']['candidate_refresh']=value
            with self.assertRaises(q.Stop):host.legacy_event(bad)
    def test_original_authority_and_default_sdk_guards_are_still_present(self):
        self.assertEqual(original.COMMIT,'874fcc9557166d94a97026ae7c966c99fa598fa9')
        self.assertEqual(original.EXPECTED_SHA256,'cf457df91c94f6afdd0edf88b2be7b202d97dd7af4906446fe05aa52e028b8a6')
        text=(ROOT/'scripts/release/rebuild-runner.py').read_text();self.assertIn('publish_archive(partial, destination, payload)',text);self.assertIn('rebuild differs from the pinned archive',text)


class CandidateTransfer(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.public=self.root/'public';self.public.mkdir()
        self.commit='a'*40;self.tree='b'*40
        self.descriptor=copy.deepcopy(candidate.PINNED);self.descriptor.update(linux_x64_sha256=hashlib.sha256(b'SDK').hexdigest(),archive_bytes=3)
        (self.public/self.descriptor['asset_name']).write_bytes(b'SDK')
        self.binaries=[]
        for row in original.expected()['binaries']:
            name=row['name'];p=self.public/'artifacts/binaries-A'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('synthetic-'+name).encode())
            self.binaries.append({'name':name,'sha256':q.sha(p),'bytes':p.stat().st_size})
        hashes={r['name']:r['sha256'] for r in self.binaries};self.images=[];self.graphs={}
        for old in original.expected()['runtime_images'].values():
            name=old['image'];p=self.public/'artifacts/images-A'/name;p.mkdir(parents=True);(p/'synthetic').write_bytes(name.encode())
            graph=copy.deepcopy(old['oci_graph']);graph['config_digest']='sha256:'+hashlib.sha256(name.encode()).hexdigest()
            binding={'uid':'65532:65532','stamp':'portable-ghar-build-identity-v1|candidate-'+self.commit[:12]+'-go1.26.10|'+self.commit,'embedded_binaries':{n:hashes[Path(n).name] for n in old['source_to_image']['embedded_binaries']}}
            self.graphs[name]=graph;self.images.append({'image':name,'oci_graph':graph,'source_to_image':binding})
        image=next(r for r in self.images if r['image']=='runner')['oci_graph']['config_digest']
        graph=next(r for r in self.images if r['image']=='runner')['oci_graph']
        smoke=dict(index_digest=graph['index_digest'],manifest_digest=graph['manifest_digest'],config_digest=graph['config_digest'],schema_version=1,image_id=image,runner_version='2.338.0',production_smoke=True,rehearsal_smoke=True,stdout_sha256=hashlib.sha256(b'2.338.0\n').hexdigest(),stderr_sha256=hashlib.sha256(b'').hexdigest(),exit_code=0,containers_removed=True,image_removed=True)
        normal=dict(status='pass',mode='unconfigured-help',network='none',credentials_or_config_created=False,stdout_sha256='a'*64,stderr_sha256=hashlib.sha256(b'').hexdigest(),trace_sha256='b'*64)
        compiler=candidate.compiler
        toolchain=dict(version=compiler.VERSION,os='linux',arch='amd64',archive_sha256=compiler.ARCHIVE_SHA256,archive_bytes=compiler.ARCHIVE_BYTES,extracted_tree_sha256='e'*64)
        self.retained_expected=candidate.retained.receipt(ROOT)
        self.retained_expected.update(archive_sha256=self.descriptor['linux_x64_sha256'],archive_bytes=self.descriptor['archive_bytes'])
        self.proof=dict(schema_version=1,status='pass',candidate_refresh=True,source_commit=self.commit,source_tree=self.tree,compiler=toolchain,sdk_descriptor=self.descriptor,sdk_source='verified-retained-ab',sdk_build_executed_this_run=False,sdk_retained=copy.deepcopy(self.retained_expected),smoke_verifier={'sha256':'f'*64,'compiler':'go1.26.10','source_commit':self.commit,'test_source_sha256':q.sha(ROOT/'internal/productionruntime/release_artifacts_image_test.go')},binary_count=11,runtime_image_count=5,independent_AB_identical=True,final_image_smoke=smoke,**candidate.FALSE_AUTHORITY)
        self.final={**self.proof,'resource_qualification':'pass','workers_joined':True,'scope_exit_code':0};self.write_receipts()
        q.write(self.public/'payload-inventory.json',{'files':[r for r in q.inventory(self.public) if r['path'].startswith('artifacts/') or r['path']==self.descriptor['asset_name']]})
    def write_receipts(self):
        q.write(self.public/'candidate-identities.json',{'proof':self.proof,'binaries':self.binaries,'images':self.images});q.write(self.public/'RESULT.json',self.final)
    def check(self):
        from unittest import mock
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(candidate,'sdk_authority',return_value=self.descriptor))
            stack.enter_context(mock.patch.object(candidate.retained,'receipt',return_value=copy.deepcopy(self.retained_expected)))
            stack.enter_context(mock.patch.object(candidate.subprocess,'check_output',return_value=self.commit+'\n'+self.tree+'\n'))
            stack.enter_context(mock.patch.object(q,'release_functions',return_value={}))
            stack.enter_context(mock.patch.object(q,'graph',side_effect=lambda path,functions:self.graphs[path.name]))
            stack.enter_context(mock.patch.object(q,'image_binary_binding',side_effect=lambda directory,graph,name,stamp,binaries:{'uid':'65532:65532','stamp':stamp,'embedded_binaries':binaries}))
            candidate.check_upload(self.public)
    def test_closed_fixture_transfer_passes_without_any_external_execution(self):self.check()
    def test_binary_sdk_and_extra_file_mutations_are_rejected(self):
        for path in [self.public/'artifacts/binaries-A'/self.binaries[0]['name'],self.public/self.descriptor['asset_name']]:
            b=path.read_bytes();path.write_bytes(b+b'drift')
            with self.subTest(path=path.name),self.assertRaises(q.Stop):self.check()
            path.write_bytes(b)
        extra=self.public/'unapproved.json';extra.write_text('{}')
        with self.assertRaises(q.Stop):self.check()
        extra.unlink()
        path=self.public/'artifacts/binaries-A'/self.binaries[0]['name'];alias=self.root/'alias';__import__('os').link(path,alias)
        with self.assertRaises(q.Stop):self.check()
    def test_authority_resource_smoke_and_compiler_receipt_drift_are_rejected(self):
        for key,value in [('qualification_executed',True),('live_operations',True),('binary_count',10),('binary_count',11.0),('schema_version',True),('schema_version',2),('sdk_build_executed_this_run',True),('extra','unapproved')]:
            original_proof=copy.deepcopy(self.proof);original_final=copy.deepcopy(self.final);self.proof[key]=value;self.final[key]=value;self.write_receipts()
            with self.subTest(key=key),self.assertRaises(q.Stop):self.check()
            self.proof=original_proof;self.final=original_final;self.write_receipts()
        for key,value in [('resource_qualification','fail'),('workers_joined',False),('scope_exit_code',False),('scope_exit_code',1)]:
            old=self.final[key];self.final[key]=value;self.write_receipts()
            with self.subTest(key=key),self.assertRaises(q.Stop):self.check()
            self.final[key]=old;self.write_receipts()
        for location,key,value in [('compiler','version','go1.26.9'),('smoke_verifier','compiler','go1.26.9'),('compiler','extra','unapproved'),('sdk_retained','prior_sdk_startup_verified',False),('final_image_smoke','image_removed',False)]:
            before=copy.deepcopy(self.proof);self.proof[location][key]=value;self.final={**self.proof,'resource_qualification':'pass','workers_joined':True,'scope_exit_code':0};self.write_receipts()
            with self.subTest(location=location,key=key),self.assertRaises(q.Stop):self.check()
            self.proof=before;self.final={**before,'resource_qualification':'pass','workers_joined':True,'scope_exit_code':0};self.write_receipts()
    def test_immutable_layer_and_embedded_source_stamp_cannot_drift(self):
        row=next(r for r in self.images if r['image']=='runner');old=row['source_to_image']['stamp'];row['source_to_image']['stamp']='wrong';self.write_receipts()
        with self.assertRaises(q.Stop):self.check()
        row['source_to_image']['stamp']=old;self.write_receipts();self.graphs['runner']['layer_digests'][0]='sha256:'+'f'*64
        with self.assertRaises(q.Stop):self.check()


class NormalStartup(unittest.TestCase):
    def test_reuses_prepared_sdk_command_and_retains_real_help_witnesses(self):
        import types
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();work=root/'work';work.mkdir();evidence=root/'evidence';evidence.mkdir()
            # The real SDK constructor creates these once; calling it twice
            # would fail before the normal startup can run.
            (work/'tmp').mkdir();(work/'runtime').mkdir();seen=[]
            def run(command,cwd,environment):
                seen.append(command)
                (work/'normal-help.stdout').write_bytes(b'Commands: synthetic help --version\n')
                (work/'normal-help.stderr').write_bytes(b'')
                (work/'normal-help.trace').write_bytes(b"CoreCLR path = '/work/runner-source/_layout/bin/libcoreclr.so'\nExecute managed assembly exit code: 0x0\n")
            rebuild=types.SimpleNamespace(run_sdk=run)
            command=['docker','run','--label','synthetic','sdk@sha256:'+'a'*64]
            candidate.normal_startup(rebuild,work,command,{},evidence)
            self.assertEqual(command,['docker','run','--label','synthetic','sdk@sha256:'+'a'*64])
            self.assertEqual(seen[0][2:4],['--network','none'])
            candidate.validate_normal(candidate.read(evidence/'sdk-normal-startup.json'))
            self.assertEqual((evidence/'sdk-normal-startup/normal-help.stdout').read_bytes(),(work/'normal-help.stdout').read_bytes())



class FinalImageControlFlow(unittest.TestCase):
    def test_both_docker_store_identities_are_bound_without_running_a_container(self):
        for store in ('config_digest','manifest_digest','index_digest'):
            with self.subTest(store=store):self.exercise(store)
    def test_changed_loaded_configuration_or_layer_identity_is_rejected(self):
        graph={k:'sha256:'+chr(97+i)*64 for i,k in enumerate(('index_digest','manifest_digest','config_digest'))}
        config={'rootfs':{'diff_ids':['sha256:'+'d'*64]},'config':{'User':'65532:65532'}}
        good={'Id':graph['manifest_digest'],'Os':'linux','Architecture':'amd64','RootFS':{'Layers':config['rootfs']['diff_ids']},'Config':config['config']}
        self.assertEqual(candidate.verify_observation(good,graph,config),graph['manifest_digest'])
        for key,value in [('Id','sha256:'+'e'*64),('Os','windows'),('Architecture','arm64'),('Config',{'User':'0:0'}),('RootFS',{'Layers':[]})]:
            with self.subTest(key=key),self.assertRaises(q.Stop):candidate.verify_observation({**good,key:value},graph,config)
    def test_failed_cleanup_cannot_produce_a_passing_image_receipt(self):
        with self.assertRaises(q.Stop):self.exercise('manifest_digest',cleanup=False)
    def exercise(self,store,cleanup=True):
        from unittest import mock
        from contextlib import ExitStack
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();evidence=root/'evidence';evidence.mkdir();source=root/'source';source.mkdir()
            layout=evidence/'artifacts/images-A/runner';blobs=layout/'blobs/sha256';blobs.mkdir(parents=True)
            config={'rootfs':{'diff_ids':['sha256:'+'c'*64]},'config':{'User':'65532:65532','Env':['HOME=/runner']}}
            data=json.dumps(config).encode();digest=hashlib.sha256(data).hexdigest();(blobs/digest).write_bytes(data)
            graph={'index_digest':'sha256:'+'a'*64,'manifest_digest':'sha256:'+'b'*64,'config_digest':'sha256:'+digest}
            image=graph[store];observed={'Id':image,'Os':'linux','Architecture':'amd64','RootFS':{'Layers':config['rootfs']['diff_ids']},'Config':config['config']}
            q.write(root/'inputs.json',{'run_id':'123'});q.write(evidence/'candidate-build-identities.json',{'images':[{'image':'runner','oci_graph':graph}]})
            state={'loaded':False};calls=[]
            def run(args,**kwargs):
                calls.append(args)
                if args[1:3]==['image','inspect']:
                    if state['loaded'] and args[-1]==image:return subprocess.CompletedProcess(args,0,json.dumps(observed).encode()+b'\n',b'')
                    return subprocess.CompletedProcess(args,1,b'',('Error response from daemon: No such image: '+args[-1]).encode())
                if args[1:3]==['image','rm']:
                    if cleanup and args[-1]==image:state['loaded']=False
                    return subprocess.CompletedProcess(args,0,b'',b'')
                if args[1:3]==['rm','--force']:return subprocess.CompletedProcess(args,0,b'',b'')
                if args[0]==str(root/'final-image-smoke.test'):
                    self.assertEqual(kwargs['env']['PGHAR_FINAL_IMAGE_ID'],image)
                    row=json.dumps({'image_id':image,'runner_version':'2.338.0'})
                    return subprocess.CompletedProcess(args,0,('source_test.go: FINAL_IMAGE_SMOKE_RECEIPT='+row+'\n').encode(),b'')
                raise AssertionError('unexpected external command')
            def command(args):
                calls.append(args)
                if args[1:3]==['image','load']:state['loaded']=True;return ''
                if args[1:3]==['ps','-aq']:return ''
                raise AssertionError('unexpected command')
            def rehearsal(actual,version,name,**kwargs):
                self.assertEqual((actual,version),(image,'2.338.0'))
                wrapper=(root/'final-smoke-bin/docker').read_text();self.assertIn('--pull=never',wrapper);self.assertIn('--cgroup-parent',wrapper);self.assertIn('DOCKER_CONFIG',wrapper)
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(q,'graph',return_value=graph));stack.enter_context(mock.patch.object(q,'release_functions',return_value={'verify_final_runner_smoke':rehearsal}));stack.enter_context(mock.patch.object(candidate,'sdk_authority',return_value={'upstream_version':'v2.338.0'}));stack.enter_context(mock.patch.object(candidate.shutil,'which',return_value='/synthetic/docker'));stack.enter_context(mock.patch.object(candidate.subprocess,'run',side_effect=run))
                candidate.smoke_image(root,{'PATH':'/synthetic','HOME':str(root/'home')},'synthetic.slice','synthetic-label',command)
            self.assertFalse(state['loaded']);self.assertEqual(sum(a[1:3]==['image','load'] for a in calls),1)
            candidate.validate_smoke(candidate.read(evidence/'candidate-image-smoke.json'),graph,'2.338.0')

if __name__=='__main__':unittest.main()
