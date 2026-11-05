# SPDX-License-Identifier: MPL-2.0
"""Closed retained-fetch diagnostics using synthetic, network-blocked replies."""
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import traceback
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
SPEC = importlib.util.spec_from_file_location('retained_fetch_diagnostics',
                                            ROOT / 'scripts/release/fetch-retained-runner.py')
FETCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FETCH)
SENTINEL = 'SYNTHETIC-PRIVATE-DIAGNOSTIC-CONTENT'
API_URL = FETCH.API + '/repos/' + FETCH.REPOSITORY + '/releases/1'
CDN_URL = 'https://release-assets.githubusercontent.com/synthetic?signature=' + SENTINEL
PHASES = ('release-metadata', 'tag-reference', 'annotated-tag', 'signed-commit',
          'release-assets', 'binary-asset', 'unattributed')


class Reply(io.BytesIO):
    def __init__(self, data=b'', status=200):
        super().__init__(data)
        self.status = status


class Unprintable:
    def __str__(self):
        raise AssertionError('untrusted value formatted')

    __repr__ = __str__


class ForgedPhase(str):
    def __str__(self):
        return SENTINEL


class ForgedStatus(int):
    def __str__(self):
        return SENTINEL


class RetainedFetchDiagnostics(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch('socket.socket', side_effect=AssertionError('network forbidden')))
        self.enterContext(mock.patch('socket.create_connection', side_effect=AssertionError('network forbidden')))
        self.enterContext(mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')))
        self.run = self.enterContext(mock.patch('subprocess.run', side_effect=AssertionError('subprocess forbidden')))
        self.popen = self.enterContext(mock.patch('subprocess.Popen', side_effect=AssertionError('subprocess forbidden')))
        self.sleep = self.enterContext(mock.patch.object(FETCH.time, 'sleep', side_effect=AssertionError('retry forbidden')))
        self.enterContext(mock.patch.dict(os.environ, {'GH_TOKEN': SENTINEL, 'GITHUB_TOKEN': SENTINEL}))
        self.opener = mock.Mock()
        self.build = self.enterContext(mock.patch.object(FETCH.urllib.request, 'build_opener', return_value=self.opener))

    def tearDown(self):
        self.run.assert_not_called()
        self.popen.assert_not_called()
        self.sleep.assert_not_called()
        for call in self.opener.open.call_args_list:
            request = call.args[0]
            self.assertEqual(call.kwargs, {'timeout': 30})
            self.assertNotIn('authorization', {key.lower() for key in request.headers})
        for call in self.build.call_args_list:
            self.assertEqual(len(call.args), 1)
            self.assertIsInstance(call.args[0], FETCH.NoRedirect)

    def error(self, status, location=CDN_URL):
        return urllib.error.HTTPError(API_URL + '?private=' + SENTINEL, status,
                                      SENTINEL, {'Location': location, 'X-Private': SENTINEL},
                                      io.BytesIO(SENTINEL.encode()))

    def refused(self, operation, prefix, phase='unattributed', stage='api', status='unknown', suppressed=True):
        try:
            operation()
        except FETCH.q.Stop as error:
            self.assertEqual(str(error), prefix + ' (phase=' + phase + '; stage=' + stage + '; status=' + str(status) + ')')
            self.assertLessEqual(len(str(error)), 160)
            self.assertIsNone(error.__cause__)
            if suppressed:
                self.assertTrue(error.__suppress_context__)
            rendered = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
            for private in (SENTINEL, API_URL, 'release-assets.githubusercontent.com', 'X-Private'):
                self.assertNotIn(private, rendered)
            return error
        self.fail('request unexpectedly succeeded')

    def test_metadata_http_statuses_are_distinct_without_retry(self):
        for status in (301, 302, 303, 307, 308, 403, 429, 500, 502, 503, 599):
            with self.subTest(status=status):
                error = self.error(status)
                self.opener.open.reset_mock(side_effect=True)
                self.opener.open.side_effect = error
                self.refused(lambda: FETCH.api('releases/1'), 'retained release response or redirect refused', status=status)
                self.opener.open.assert_called_once()
                self.assertTrue(error.fp.closed)

    def test_all_phases_are_explicit_and_unknown_phase_cannot_leak(self):
        for phase in (*PHASES, SENTINEL, 'release-metadata\n' + SENTINEL, [], {},
                      None, Unprintable(), ForgedPhase('release-metadata')):
            self.opener.open.side_effect = self.error(403)
            expected = phase if type(phase) is str and phase in PHASES else 'unattributed'
            self.refused(lambda: FETCH.api('releases/1?private=' + SENTINEL, phase=phase),
                         'retained release response or redirect refused', phase=expected, status=403)

    def test_diagnostic_stage_is_closed_even_for_arbitrary_internal_input(self):
        for stage in ('api', 'cdn', SENTINEL, [], {}, None, Unprintable(), ForgedPhase('api')):
            expected = stage if type(stage) is str and stage in ('api', 'cdn') else 'unattributed'
            self.assertEqual(FETCH.request_diagnostic('release-metadata', stage, 403),
                             '(phase=release-metadata; stage=' + expected + '; status=403)')

    def test_status_is_exact_integer_in_closed_http_range(self):
        for status in (100, 199, 299, 399, 599, 99, 600, -1, 10**1000, True, False,
                       None, 403.0, '403', SENTINEL, [], {}, Unprintable(), ForgedStatus(403)):
            self.opener.open.side_effect = self.error(status)
            expected = status if type(status) is int and 100 <= status <= 599 else 'unknown'
            self.refused(lambda: FETCH.api('releases/1'),
                         'retained release response or redirect refused', status=expected)

    def test_malformed_metadata_location_is_refused_without_disclosure(self):
        for status in (302, 403, 429, 503):
            self.opener.open.side_effect = self.error(status, 'https://[' + SENTINEL)
            self.refused(lambda: FETCH.api('releases/1', phase='release-metadata'),
                         'retained release response or redirect refused', phase='release-metadata', status=status)

    def test_binary_api_and_cdn_http_failures_are_distinguishable(self):
        for status in (302, 403, 429, 500, 503):
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = self.error(status, 'https://example.invalid/' + SENTINEL)
            self.refused(lambda: FETCH.transfer(API_URL, io.BytesIO(), 1, binary=True, phase='binary-asset'),
                         'retained release response or redirect refused', phase='binary-asset', status=status)
            self.opener.open.assert_called_once()
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = [self.error(302), self.error(status)]
            self.refused(lambda: FETCH.transfer(API_URL, io.BytesIO(), 1, binary=True, phase='binary-asset'),
                         'retained binary transport failed', phase='binary-asset', stage='cdn', status=status)
            self.assertEqual(self.opener.open.call_count, 2)

    def test_api_and_cdn_transport_errors_have_unknown_status_and_no_exception_chain(self):
        for transport in (urllib.error.URLError(SENTINEL), OSError(SENTINEL)):
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = transport
            self.refused(lambda: FETCH.api('releases/1', phase='release-metadata'),
                         'retained release transport failed', phase='release-metadata')
            self.opener.open.assert_called_once()
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = [self.error(302), transport]
            self.refused(lambda: FETCH.transfer(API_URL, io.BytesIO(), 1, binary=True, phase='binary-asset'),
                         'retained binary transport failed', phase='binary-asset', stage='cdn')
            self.assertEqual(self.opener.open.call_count, 2)

    def test_http_protocol_errors_are_private_at_api_cdn_and_read(self):
        for error_type in (http.client.BadStatusLine, http.client.InvalidURL, http.client.IncompleteRead):
            for stage in ('api', 'cdn', 'api-read', 'cdn-read'):
                with self.subTest(error=error_type.__name__, stage=stage):
                    error = error_type(SENTINEL)
                    self.opener.open.reset_mock(side_effect=True)
                    redirected = stage.startswith('cdn')
                    responses = [self.error(302)] if redirected else []
                    if stage.endswith('-read'):
                        response = Reply()
                        response.read = mock.Mock(side_effect=[b'a', error])
                        responses.append(response)
                        prefix = 'retained release read failed'
                    else:
                        responses.append(error)
                        prefix = 'retained binary transport failed' if redirected else 'retained release transport failed'
                    self.opener.open.side_effect = responses
                    output = io.BytesIO()
                    self.refused(lambda: FETCH.transfer(API_URL, output, 3, binary=True, phase='binary-asset'),
                                 prefix, phase='binary-asset', stage='cdn' if redirected else 'api')
                    self.assertEqual(self.opener.open.call_count, 2 if redirected else 1)
                    self.assertEqual(output.getvalue(), b'a' if stage.endswith('-read') else b'')
                    if stage.endswith('-read'):
                        self.assertEqual(response.read.call_args_list, [mock.call(4), mock.call(3)])
                        self.assertTrue(response.closed)

    def test_read_errors_preserve_partial_output_and_suppress_private_exception_text(self):
        for redirected in (False, True):
            for kind in ('http', 'url', 'os'):
                error = {'http': self.error(503), 'url': urllib.error.URLError(SENTINEL),
                         'os': OSError(SENTINEL)}[kind]
                response = Reply()
                response.read = mock.Mock(side_effect=[b'a', error])
                self.opener.open.reset_mock(side_effect=True)
                self.opener.open.side_effect = ([self.error(302)] if redirected else []) + [response]
                output = io.BytesIO()
                self.refused(lambda: FETCH.transfer(API_URL, output, 3, binary=True, phase='binary-asset'),
                             'retained release read failed', phase='binary-asset',
                             stage='cdn' if redirected else 'api', status=503 if kind == 'http' else 'unknown')
                self.assertEqual(output.getvalue(), b'a')
                self.assertEqual(response.read.call_args_list, [mock.call(4), mock.call(3)])
                self.assertEqual(self.opener.open.call_count, 2 if redirected else 1)
                self.assertTrue(response.closed)

    def test_response_status_refusal_uses_closed_fields_at_both_stages(self):
        for status in (201, 302, 403, 429, 503, 99, 600, True, SENTINEL, ForgedStatus(403)):
            for redirected in (False, True):
                response = Reply(SENTINEL.encode(), status)
                self.opener.open.reset_mock(side_effect=True)
                self.opener.open.side_effect = ([self.error(302)] if redirected else []) + [response]
                expected = status if type(status) is int and 100 <= status <= 599 else 'unknown'
                self.refused(lambda: FETCH.transfer(API_URL, io.BytesIO(), 100, binary=True, phase='binary-asset'),
                             'retained release response refused', phase='binary-asset',
                             stage='cdn' if redirected else 'api', status=expected, suppressed=False)
                self.assertEqual(self.opener.open.call_count, 2 if redirected else 1)
                self.assertTrue(response.closed)

    def test_redirect_authority_and_zero_or_one_redirect_policy_are_unchanged(self):
        locations = ('http://release-assets.githubusercontent.com/file', 'https://example.invalid/file',
                     'https://release-assets.githubusercontent.com.example.invalid/file',
                     'https://user@release-assets.githubusercontent.com/file',
                     'https://user:secret@release-assets.githubusercontent.com/file',
                     'https://release-assets.githubusercontent.com:443/file',
                     'https://release-assets.githubusercontent.com/file#' + SENTINEL,
                     'https://[' + SENTINEL, '//release-assets.githubusercontent.com/file', '')
        for location in locations:
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = self.error(302, location)
            self.refused(lambda: FETCH.transfer(API_URL, io.BytesIO(), 1, binary=True),
                         'retained release response or redirect refused', status=302)
            self.opener.open.assert_called_once()
        for status in (301, 303, 307, 308):
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = self.error(status)
            self.refused(lambda: FETCH.transfer(API_URL, io.BytesIO(), 1, binary=True),
                         'retained release response or redirect refused', status=status)
            self.opener.open.assert_called_once()
        request = FETCH.urllib.request.Request(API_URL)
        self.assertIsNone(FETCH.NoRedirect().redirect_request(request, None, 302, SENTINEL, {}, CDN_URL))

    def test_success_keeps_exact_bytes_headers_and_call_counts(self):
        for redirected in (False, True):
            self.opener.open.reset_mock(side_effect=True)
            self.opener.open.side_effect = ([self.error(302)] if redirected else []) + [Reply(b'abc')]
            output = io.BytesIO()
            FETCH.transfer(API_URL, output, 3, binary=True, phase='binary-asset')
            self.assertEqual(output.getvalue(), b'abc')
            self.assertEqual(self.opener.open.call_count, 2 if redirected else 1)
            api_headers = self.opener.open.call_args_list[0].args[0].headers
            self.assertEqual(api_headers, {'Accept': 'application/octet-stream',
                                          'User-agent': 'portable-ghar-retained-input',
                                          'X-github-api-version': '2026-03-10'})
            if redirected:
                self.assertEqual(self.opener.open.call_args_list[1].args[0].headers,
                                 {'User-agent': 'portable-ghar-retained-input'})
                self.assertEqual(self.opener.open.call_args_list[1].args[0].full_url, CDN_URL)
        self.opener.open.side_effect = [Reply(b'{"synthetic":true}')]
        self.assertEqual(FETCH.api('releases/1', phase='release-metadata'), {'synthetic': True})
        self.assertEqual(self.opener.open.call_args.args[0].headers['Accept'], 'application/vnd.github+json')

    def test_origin_bytes_deadline_and_json_refusals_are_unchanged(self):
        with self.assertRaisesRegex(FETCH.q.Stop, '^unexpected retained release API origin$'):
            FETCH.transfer('https://example.invalid/' + SENTINEL, io.BytesIO(), 3)
        self.build.assert_not_called()
        self.opener.open.assert_not_called()
        for redirected in (False, True):
            self.opener.open.side_effect = ([self.error(302)] if redirected else []) + [Reply(b'abcd')]
            output = io.BytesIO()
            with self.assertRaisesRegex(FETCH.q.Stop, '^retained release bytes exceed bound$'):
                FETCH.transfer(API_URL, output, 3, binary=True)
            self.assertEqual(output.getvalue(), b'')
        self.opener.open.side_effect = [Reply(b'abc')]
        with mock.patch.object(FETCH.time, 'monotonic', side_effect=[0, 121]):
            with self.assertRaisesRegex(FETCH.q.Stop, '^retained release transfer deadline exceeded$'):
                FETCH.transfer(API_URL, io.BytesIO(), 3)
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            self.opener.open.side_effect = [Reply(data)]
            with self.assertRaises(FETCH.q.Stop):
                FETCH.api('releases/1')

    def main_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        observation = root / 'accounting.json'
        observation.write_text(json.dumps(dict(read_only_accounting_preflight='pass',
                                               retained_bootstrap_admitted=True, source=str(root),
                                               observed_at=time.time())))
        value = dict(release_id=1, tag='sdk-input-test', commit_sha='a' * 40)
        data = {'synthetic.tar.gz': b'synthetic archive', FETCH.retained.RECEIPT_NAME: b'synthetic receipt'}
        rows = [dict(id=i, name=name) for i, name in enumerate(data, 1)]
        expected = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for name, raw in data.items()}
        answers = [dict(id=1, tag_name=value['tag'], draft=False, immutable=True, prerelease=True),
                   dict(ref='refs/tags/' + value['tag'], object=dict(type='tag', sha='b' * 40)),
                   dict(sha='b' * 40, tag=value['tag'], object=dict(type='commit', sha='a' * 40)),
                   dict(sha='a' * 40, verification=dict(verified=True)), rows]
        self.enterContext(mock.patch.object(FETCH, 'ROOT', root))
        self.enterContext(mock.patch.object(FETCH, 'locator', return_value=value))
        self.enterContext(mock.patch.object(FETCH.os, 'statvfs', return_value=mock.Mock(
            f_bavail=40 * 2**30, f_frsize=1, f_favail=1000000)))
        self.enterContext(mock.patch.object(FETCH, 'release_assets', return_value=expected))
        checked = self.enterContext(mock.patch.object(FETCH.retained, 'checked_file', wraps=FETCH.retained.checked_file))
        verify = self.enterContext(mock.patch.object(FETCH.retained, 'verify_inputs'))
        return root, observation, answers, data, checked, verify

    def test_main_attaches_each_phase_before_request_and_stops_immediately(self):
        for failed_index, phase in enumerate(PHASES[:-1]):
            with self.subTest(phase=phase):
                root, observation, answers, data, checked, verify = self.main_fixture()
                self.opener.open.reset_mock(side_effect=True)
                replies = [Reply(json.dumps(row).encode()) for row in answers[:failed_index]]
                self.opener.open.side_effect = [*replies, self.error(429)]
                self.refused(lambda: FETCH.main(observation), 'retained release response or redirect refused',
                             phase=phase, status=429)
                self.assertEqual(self.opener.open.call_count, failed_index + 1)
                verify.assert_not_called()
                checked.assert_not_called()
                if failed_index < 5:
                    self.assertFalse((root / FETCH.retained.INPUT_NAME).exists())

    def test_main_keeps_exact_signed_source_asset_hash_and_input_checks(self):
        root, observation, answers, data, checked, verify = self.main_fixture()
        self.opener.open.side_effect = [*(Reply(json.dumps(row).encode()) for row in answers),
                                       Reply(data['synthetic.tar.gz']), self.error(302),
                                       Reply(data[FETCH.retained.RECEIPT_NAME])]
        with mock.patch.object(FETCH, 'release_identity', wraps=FETCH.release_identity) as identity:
            FETCH.main(observation)
        identity.assert_called_once()
        self.assertEqual(self.opener.open.call_count, 8)
        self.assertEqual(checked.call_count, 2)
        destination = root / FETCH.retained.INPUT_NAME
        verify.assert_called_once_with(root, destination)
        for name, raw in data.items():
            self.assertEqual((destination / name).read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
