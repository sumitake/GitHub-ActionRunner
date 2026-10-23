"""Focused compiler transport, provenance and refreshed-subject admission checks."""
# SPDX-License-Identifier: MPL-2.0
import copy
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
import _go_patch_refresh as refresh
import _payload_reconstruction as original
import _bounded_qualification as q


class GoPatchRefresh(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()

    def archive(self, members=None):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w:gz') as stream:
            for name, kind, mode, body in members or [('go/bin/go', tarfile.REGTYPE, 0o755, b'go'), ('go/pkg/tool/linux_amd64/compile', tarfile.REGTYPE, 0o755, b'compiler')]:
                row = tarfile.TarInfo(name)
                row.type, row.mode = kind, mode
                row.size = len(body) if kind == tarfile.REGTYPE else 0
                row.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                stream.addfile(row, io.BytesIO(body))
        return raw.getvalue()

    def test_official_descriptor_matches_executable_pin_and_original_authority_stays_fixed(self):
        descriptor = json.loads((ROOT / 'release/go-patch-refresh.json').read_text())
        self.assertEqual((descriptor['archive_sha256'], descriptor['archive_bytes'], descriptor['url'], descriptor['version']), (refresh.ARCHIVE_SHA256, refresh.ARCHIVE_BYTES, refresh.URL, refresh.VERSION))
        self.assertEqual(descriptor['source_commit'], original.COMMIT)
        self.assertEqual(original.expected()['file_count'], 63)
        self.assertEqual(original.EXPECTED_SHA256, 'cf457df91c94f6afdd0edf88b2be7b202d97dd7af4906446fe05aa52e028b8a6')

    def test_download_is_length_and_hash_pinned_and_extracted_compiler_is_readonly(self):
        raw = self.archive()
        with mock.patch.object(refresh, 'open_official', return_value=io.BytesIO(raw)), mock.patch.object(refresh, 'ARCHIVE_BYTES', len(raw)), mock.patch.object(refresh, 'ARCHIVE_SHA256', hashlib.sha256(raw).hexdigest()):
            root, proof = refresh.acquire(self.root / 'compiler')
        self.assertEqual((root / 'bin/go').stat().st_mode & 0o777, 0o555)
        self.assertEqual(proof['extracted_tree_sha256'], refresh.compiler_identity(root))
        (root / 'bin/go').chmod(0o755)
        with self.assertRaises(q.Stop): refresh.compiler_identity(root)

    def test_size_hash_and_existing_destination_fail_before_compiler_use(self):
        for case in ('short', 'long', 'hash', 'existing'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.root) as temp:
                destination = pathlib.Path(temp) / 'compiler'
                raw = self.archive()
                if case == 'existing': destination.mkdir()
                with mock.patch.object(refresh, 'open_official', return_value=io.BytesIO(raw)), mock.patch.object(refresh, 'ARCHIVE_BYTES', len(raw) + (1 if case == 'short' else -1 if case == 'long' else 0)), mock.patch.object(refresh, 'ARCHIVE_SHA256', '0' * 64), self.assertRaises(q.Stop):
                    refresh.acquire(destination)
                self.assertFalse((destination / 'go/bin/go').exists())

    def test_archive_links_traversal_duplicate_privileged_mode_and_expansion_are_refused(self):
        cases = [[('../escape', tarfile.REGTYPE, 0o644, b'x')], [('go/bin/go', tarfile.SYMTYPE, 0o777, b'')], [('go/bin/go', tarfile.LNKTYPE, 0o644, b'')], [('go/bin/go', tarfile.REGTYPE, 0o4755, b'x')], [('go/bin/go', tarfile.REGTYPE, 0o775, b'x')], [('go/bin/go', tarfile.REGTYPE, 0o755, b'x')] * 2]
        for index, members in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=self.root) as temp:
                archive = pathlib.Path(temp) / 'input.tar.gz'
                archive.write_bytes(self.archive(members))
                with self.assertRaises(q.Stop): refresh.extract(archive, pathlib.Path(temp))
        archive = self.root / 'large.tar.gz'
        archive.write_bytes(self.archive())
        with mock.patch.object(refresh, 'MAX_EXTRACTED', 1), self.assertRaises(q.Stop): refresh.extract(archive, self.root)

    def image(self, directory, name, binding, count, mutation=None):
        blobs=directory/'blobs/sha256';blobs.mkdir(parents=True)
        def blob(body, media):
            digest=hashlib.sha256(body).hexdigest();(blobs/digest).write_bytes(body)
            return {'mediaType':media,'digest':'sha256:'+digest,'size':len(body)}
        slots=[i for i in range(count) if i not in refresh.NON_GO_LAYERS[name]]
        targets=dict(zip(slots,sorted(binding)))
        layers=[]
        for i in range(count):
            path=targets.get(i,'unchanged/'+name+'/'+str(i))
            data=binding[path] if i in targets else b'original non-Go layer'
            if mutation=='embedded' and i in targets: data=b'wrong Go executable'
            if mutation=='non_go' and i==0: data=b'changed immutable layer'
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as archive:
                member=tarfile.TarInfo(path);member.mode=0o555 if i in targets else 0o444;member.size=len(data);archive.addfile(member,io.BytesIO(data))
            layers.append(blob(stream.getvalue(),'application/vnd.oci.image.layer.v1.tar'))
        config={'architecture':'amd64','os':'linux','config':{'User':'0:0' if mutation=='uid' else '65532:65532'},'rootfs':{'type':'layers','diff_ids':[row['digest'] for row in layers]}}
        if name=='runner': config['config']['Env']=['HOME=/runner','LANG=C.UTF-8','PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','XDG_RUNTIME_DIR=/tmp']
        if mutation=='env': config['config']['Env'].append('UNEXPECTED=value')
        config_blob=blob(json.dumps(config).encode(),'application/vnd.oci.image.config.v1+json')
        manifest=blob(json.dumps({'schemaVersion':2,'config':config_blob,'layers':layers}).encode(),'application/vnd.oci.image.manifest.v1+json');manifest['platform']={'os':'linux','architecture':'amd64'}
        (directory/'index.json').write_text(json.dumps({'schemaVersion':2,'manifests':[manifest]}));(directory/'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
        return q.graph(directory,q.release_functions(ROOT))

    def fixture(self):
        authority=copy.deepcopy(original.expected())
        public=self.root/'public';artifacts=public/'artifacts';binaries=[]
        stamp='portable-ghar-build-identity-v1|candidate-'+original.COMMIT[:12]+'-go1.26.10|'+original.COMMIT
        for row in authority['binaries']:
            path=artifacts/'binaries-A'/row['name'];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((row['name']+stamp).encode())
            binaries.append({'name':row['name'],'bytes':path.stat().st_size,'sha256':q.sha(path)});row['sha256']='0'*64
        by_name={row['name']:row['sha256'] for row in binaries};images=[]
        for old in authority['runtime_images'].values():
            name=old['image'];count=len(old['oci_graph']['layer_digests'])
            binding={path:(artifacts/'binaries-A'/pathlib.PurePosixPath(path).name).read_bytes() for path in old['source_to_image']['embedded_binaries']}
            old['oci_graph']=self.image(self.root/'old'/name,name,{path:b'old Go bytes' for path in binding},count)
            images.append({'image':name,'oci_graph':self.image(artifacts/'images-A'/name,name,binding,count),'source_to_image':{'uid':'65532:65532','stamp':stamp,'embedded_binaries':{path:by_name[pathlib.PurePosixPath(path).name] for path in binding}}})
        proof=dict(source_toolchain_directive='go1.26.9',explicit_compiler_override=True,binary_toolchain_checks=22,schema_version=1,status='pass',go_patch_refresh=True,reconstruction_matched=False,source_commit=original.COMMIT,source_tree=original.TREE,original_authority_sha256=original.EXPECTED_SHA256,tooling_commit='a'*40,tooling_tree='b'*40,compiler={'version':refresh.VERSION,'os':'linux','arch':'amd64','archive_sha256':refresh.ARCHIVE_SHA256,'archive_bytes':refresh.ARCHIVE_BYTES,'extracted_tree_sha256':'c'*64},version='candidate-'+original.COMMIT[:12]+'-go1.26.10',binary_count=11,runtime_image_count=5,independent_AB_identical=True,focused_checks=refresh.FOCUSED,sdk_archive_sha256=refresh.SDK_SHA256,sdk_archive_bytes=refresh.SDK_BYTES,sdk_dotnet_unchanged=True,qualification_executed=False,release_admitted=False,target_conformance_executed=False,live_operations=False)
        q.write(public/'go-refresh-identities.json',{'proof':proof,'binaries':binaries,'images':images});q.write(public/'RESULT.json',{**proof,'resource_qualification':'pass','workers_joined':True,'scope_exit_code':0});self.inventory(public)
        return public,authority

    def inventory(self,public):
        q.write(public/'payload-inventory.json',{'files':[{'path':'artifacts/'+row['path'],'bytes':row['bytes'],'sha256':row['sha256']} for row in q.inventory(public/'artifacts')]})

    def test_upload_rehash_rejects_payload_mutation_extra_metadata_and_false_old_hash_claim(self):
        for mutation in ('bytes','extra','old_claim','compiler','sdk','resources','embedded','field'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(dir=self.root) as temp:
                previous=self.root;self.root=pathlib.Path(temp).resolve();public,authority=self.fixture()
                with mock.patch.object(original,'expected',return_value=authority):
                    refresh.check_upload(public);identities=original.read_json(public/'go-refresh-identities.json')
                    if mutation=='bytes': next((public/'artifacts/binaries-A').iterdir()).write_bytes(b'drift')
                    elif mutation=='extra': (public/'native.log').write_text('private')
                    elif mutation=='resources':
                        final=original.read_json(public/'RESULT.json');final['resource_qualification']='fail';q.write(public/'RESULT.json',final)
                    elif mutation=='embedded': identities['images'][0]['source_to_image']['embedded_binaries']={}
                    else:
                        if mutation=='old_claim': identities['proof']['reconstruction_matched']=True
                        elif mutation=='compiler': identities['proof']['compiler']['archive_sha256']='0'*64
                        elif mutation=='sdk': identities['proof']['sdk_archive_sha256']='0'*64
                        else: identities['proof']['unexpected']='private'
                        q.write(public/'RESULT.json',{**identities['proof'],'resource_qualification':'pass','workers_joined':True,'scope_exit_code':0})
                    q.write(public/'go-refresh-identities.json',identities)
                    with self.assertRaises(q.Stop): refresh.check_upload(public)
                self.root=previous

    def test_merkle_valid_images_still_require_actual_binary_uid_environment_and_unchanged_layers(self):
        import shutil
        for mutation in ('embedded','uid','env','non_go','old_binary','old_image','root_link'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(dir=self.root) as temp:
                previous=self.root;self.root=pathlib.Path(temp).resolve();public,authority=self.fixture();identities=original.read_json(public/'go-refresh-identities.json')
                if mutation in ('embedded','uid','env','non_go'):
                    image=next(row for row in identities['images'] if row['image']=='runner');directory=public/'artifacts/images-A/runner';shutil.rmtree(directory)
                    binding={path:(public/'artifacts/binaries-A'/pathlib.PurePosixPath(path).name).read_bytes() for path in image['source_to_image']['embedded_binaries']}
                    image['oci_graph']=self.image(directory,'runner',binding,5,mutation);q.write(public/'go-refresh-identities.json',identities);self.inventory(public)
                elif mutation=='old_binary': authority['binaries'][0]['sha256']=identities['binaries'][0]['sha256']
                elif mutation=='old_image':
                    image=identities['images'][0];next(row for row in authority['runtime_images'].values() if row['image']==image['image'])['oci_graph']=image['oci_graph']
                else:
                    link=self.root/'alias';link.symlink_to(public,target_is_directory=True);public=link
                with mock.patch.object(original,'expected',return_value=authority),self.assertRaises(q.Stop): refresh.check_upload(public)
                self.root=previous

    def test_redirects_must_remain_official_https_and_directory_mode_changes_break_seal(self):
        handler=refresh.OfficialHTTPS();request=refresh.urllib.request.Request(refresh.URL)
        for url in ('http://dl.google.com/go/archive','https://example.invalid/archive','https://user:pass@dl.google.com/archive'):
            with self.subTest(url=url),self.assertRaises(q.Stop):handler.redirect_request(request,None,302,'redirect',{},url)
        redirected=handler.redirect_request(request,None,302,'redirect',{},'https://dl.google.com/go/archive');self.assertEqual(redirected.full_url,'https://dl.google.com/go/archive')
        archive=self.root/'go.tar.gz';archive.write_bytes(self.archive());root=refresh.extract(archive,self.root);refresh.compiler_identity(root);(root/'bin').chmod(0o755)
        with self.assertRaises(q.Stop):refresh.compiler_identity(root)

    def test_compiler_override_is_explicit_and_tooling_pins_track_the_patch(self):
        with self.assertRaises(q.Stop): refresh.constrain_compiler(self.root, {'GOROOT':'/old/go','PATH':'/usr/bin'})
        environment=refresh.constrain_compiler(self.root, {'GOROOT':'/toolchain/go','PATH':'/toolchain/go/bin:/usr/bin'})
        self.assertTrue(environment['PATH'].startswith(str(self.root/'fixed-go-bin')+':'))
        self.assertEqual((self.root/'fixed-go-bin/go').stat().st_mode & 0o777,0o555)
        self.assertIn('toolchain go1.26.10', (ROOT/'go.mod').read_text())
        self.assertIn('GoToolchain:       "go1.26.10"', (ROOT/'internal/buildinfo/pins.go').read_text())
        self.assertIn('\\ntoolchain go1.26.10\\n', (ROOT/'tests/boundaries/runtime_boundary_test.go').read_text())

    def test_refresh_bootstrap_does_not_select_an_unaccounted_compiler(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('refresh_bootstrap_host', ROOT/'scripts/release/qualify-runtime.py')
        host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
        with mock.patch.dict(os.environ, {}, clear=True):
            environment=host.safe_environment(self.root,None)
        self.assertNotIn('GOROOT',environment)
        self.assertEqual(environment['PATH'],'/usr/local/bin:/usr/bin:/bin')
        self.assertEqual(environment['GOTOOLCHAIN'],'local')

    def test_refresh_cannot_enter_the_old_exact_reconstruction_profile(self):
        worker=object.__new__(q.Qualification)
        with self.assertRaises(q.Stop):
            worker.build(reconstruction=True,go_patch_refresh=True)


if __name__ == '__main__':
    unittest.main()
