package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	officialRunnerAPI               = "https://api.github.com"
	officialRunnerAccept            = "application/vnd.github+json"
	officialRunnerAPIVersion        = "2022-11-28"
	officialRunnerObserverUserAgent = "portable-ghar-runner-release-observer/1"
	defaultReleaseBodyBytes         = int64(1 << 20)
	defaultReleaseRequestTimeout    = 10 * time.Second
	maxReleaseAssets                = 256
	runnerReleaseEvidenceDomain     = "portable-ghar-runner-release-observation-v1"
)

var ErrRunnerReleaseObservation = errors.New(
	"upgrade: runner release observation failed",
)

// OfficialRunnerReleaseObserver observes only the fixed official
// actions/runner GitHub API endpoints.
type OfficialRunnerReleaseObserver struct {
	client         *http.Client
	maxBodyBytes   int64
	requestTimeout time.Duration
}

// NewOfficialRunnerReleaseObserver returns the fixed-origin production
// observer. Callers must still provide a bounded context deadline to Observe.
func NewOfficialRunnerReleaseObserver() *OfficialRunnerReleaseObserver {
	observer, _ := newOfficialRunnerReleaseObserver(
		&http.Client{Transport: http.DefaultTransport},
		defaultReleaseBodyBytes,
		defaultReleaseRequestTimeout,
	)
	return observer
}

func newOfficialRunnerReleaseObserver(
	client *http.Client,
	maxBodyBytes int64,
	requestTimeout time.Duration,
) (*OfficialRunnerReleaseObserver, error) {
	if client == nil ||
		maxBodyBytes <= 0 ||
		requestTimeout <= 0 {
		return nil, ErrRunnerReleaseObservation
	}
	cloned := *client
	if cloned.Transport == nil {
		cloned.Transport = http.DefaultTransport
	}
	cloned.CheckRedirect = func(
		_ *http.Request,
		_ []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	return &OfficialRunnerReleaseObserver{
		client:         &cloned,
		maxBodyBytes:   maxBodyBytes,
		requestTimeout: requestTimeout,
	}, nil
}

// Observe returns the latest exact official Linux x64 runner release.
func (observer *OfficialRunnerReleaseObserver) Observe(
	ctx context.Context,
) (RunnerRelease, error) {
	if observer == nil || ctx == nil {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	if _, ok := ctx.Deadline(); !ok {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	if err := ctx.Err(); err != nil {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}

	releaseDocument, err := observer.get(
		ctx,
		"/repos/actions/runner/releases/latest",
	)
	if err != nil {
		return RunnerRelease{}, err
	}
	release, err := parseLatestRunnerRelease(releaseDocument)
	if err != nil {
		return RunnerRelease{}, err
	}

	tagDocument, err := observer.get(
		ctx,
		"/repos/actions/runner/git/ref/tags/"+
			url.PathEscape(release.Version),
	)
	if err != nil {
		return RunnerRelease{}, err
	}
	tagRefSHA, sourceCommitSHA, annotated, err := parseRunnerTagRef(
		tagDocument,
		release.Version,
	)
	if err != nil {
		return RunnerRelease{}, err
	}
	if annotated {
		tagObjectDocument, fetchErr := observer.get(
			ctx,
			"/repos/actions/runner/git/tags/"+tagRefSHA,
		)
		if fetchErr != nil {
			return RunnerRelease{}, fetchErr
		}
		sourceCommitSHA, err = parseAnnotatedRunnerTag(
			tagObjectDocument,
			release.Version,
		)
		if err != nil {
			return RunnerRelease{}, err
		}
	}
	release.TagRefSHA = tagRefSHA
	release.SourceCommitSHA = sourceCommitSHA
	release.ObservationEvidence = runnerReleaseEvidenceDigest(release)
	if err := release.Validate(); err != nil {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	return release, nil
}

func (observer *OfficialRunnerReleaseObserver) get(
	ctx context.Context,
	path string,
) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, observer.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		officialRunnerAPI+path,
		nil,
	)
	if err != nil {
		return nil, ErrRunnerReleaseObservation
	}
	request.Header.Set("Accept", officialRunnerAccept)
	request.Header.Set("X-GitHub-Api-Version", officialRunnerAPIVersion)
	request.Header.Set("User-Agent", officialRunnerObserverUserAgent)
	response, err := observer.client.Do(request)
	if err != nil {
		return nil, ErrRunnerReleaseObservation
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.ContentLength > observer.maxBodyBytes {
		return nil, ErrRunnerReleaseObservation
	}
	document, err := io.ReadAll(io.LimitReader(
		response.Body,
		observer.maxBodyBytes+1,
	))
	if err != nil ||
		len(document) == 0 ||
		int64(len(document)) > observer.maxBodyBytes {
		return nil, ErrRunnerReleaseObservation
	}
	return document, nil
}

func parseLatestRunnerRelease(document []byte) (RunnerRelease, error) {
	fields, err := decodeObject(document)
	if err != nil {
		return RunnerRelease{}, err
	}
	var release RunnerRelease
	var draft bool
	var prerelease bool
	var published string
	var assets []json.RawMessage
	if decodeField(fields, "tag_name", &release.Version) != nil ||
		decodeField(fields, "draft", &draft) != nil ||
		decodeField(fields, "prerelease", &prerelease) != nil ||
		decodeField(fields, "published_at", &published) != nil ||
		decodeField(fields, "assets", &assets) != nil ||
		draft ||
		prerelease ||
		len(assets) == 0 ||
		len(assets) > maxReleaseAssets {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	if _, err := parseRunnerVersion(release.Version); err != nil {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	publishedAt, err := time.Parse(time.RFC3339, published)
	if err != nil || publishedAt.Location() != time.UTC {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	release.PublishedAt = publishedAt

	wantName := "actions-runner-linux-x64-" +
		strings.TrimPrefix(release.Version, "v") +
		".tar.gz"
	matches := 0
	for _, rawAsset := range assets {
		assetFields, parseErr := decodeObject(rawAsset)
		if parseErr != nil {
			return RunnerRelease{}, parseErr
		}
		var name string
		var size int64
		var digest string
		if decodeField(assetFields, "name", &name) != nil ||
			decodeField(assetFields, "size", &size) != nil ||
			decodeField(assetFields, "digest", &digest) != nil {
			return RunnerRelease{}, ErrRunnerReleaseObservation
		}
		if name != wantName {
			continue
		}
		matches++
		if size <= 0 ||
			uint64(size) > maxRunnerAssetBytes ||
			!validImageDigest(digest) {
			return RunnerRelease{}, ErrRunnerReleaseObservation
		}
		release.LinuxX64AssetName = name
		release.LinuxX64AssetSize = uint64(size)
		release.LinuxX64AssetDigest = digest
	}
	if matches != 1 {
		return RunnerRelease{}, ErrRunnerReleaseObservation
	}
	return release, nil
}

func parseRunnerTagRef(
	document []byte,
	version string,
) (string, string, bool, error) {
	fields, err := decodeObject(document)
	if err != nil {
		return "", "", false, err
	}
	var ref string
	var rawObject json.RawMessage
	if decodeField(fields, "ref", &ref) != nil ||
		decodeField(fields, "object", &rawObject) != nil ||
		ref != "refs/tags/"+version {
		return "", "", false, ErrRunnerReleaseObservation
	}
	sha, objectType, err := decodeGitObject(rawObject)
	if err != nil {
		return "", "", false, err
	}
	switch objectType {
	case "commit":
		return sha, sha, false, nil
	case "tag":
		return sha, "", true, nil
	default:
		return "", "", false, ErrRunnerReleaseObservation
	}
}

func parseAnnotatedRunnerTag(
	document []byte,
	version string,
) (string, error) {
	fields, err := decodeObject(document)
	if err != nil {
		return "", err
	}
	var tag string
	var rawObject json.RawMessage
	if decodeField(fields, "tag", &tag) != nil ||
		decodeField(fields, "object", &rawObject) != nil ||
		tag != version {
		return "", ErrRunnerReleaseObservation
	}
	sha, objectType, err := decodeGitObject(rawObject)
	if err != nil || objectType != "commit" {
		return "", ErrRunnerReleaseObservation
	}
	return sha, nil
}

func decodeGitObject(document []byte) (string, string, error) {
	fields, err := decodeObject(document)
	if err != nil {
		return "", "", err
	}
	var sha string
	var objectType string
	if decodeField(fields, "sha", &sha) != nil ||
		decodeField(fields, "type", &objectType) != nil ||
		!validLowerHex(sha, 40) {
		return "", "", ErrRunnerReleaseObservation
	}
	return sha, objectType, nil
}

func decodeObject(document []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrRunnerReleaseObservation
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, ErrRunnerReleaseObservation
		}
		name, ok := token.(string)
		if !ok {
			return nil, ErrRunnerReleaseObservation
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrRunnerReleaseObservation
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrRunnerReleaseObservation
		}
		fields[name] = raw
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, ErrRunnerReleaseObservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrRunnerReleaseObservation
	}
	return fields, nil
}

func decodeField(
	fields map[string]json.RawMessage,
	name string,
	target any,
) error {
	raw, ok := fields[name]
	if !ok {
		return ErrRunnerReleaseObservation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return ErrRunnerReleaseObservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrRunnerReleaseObservation
	}
	return nil
}

func runnerReleaseEvidenceDigest(release RunnerRelease) string {
	hash := sha256.New()
	fields := [][]byte{
		[]byte(runnerReleaseEvidenceDomain),
		[]byte(release.Version),
		[]byte(release.TagRefSHA),
		[]byte(release.SourceCommitSHA),
		[]byte(release.LinuxX64AssetName),
		[]byte(stringInteger(release.LinuxX64AssetSize)),
		[]byte(release.LinuxX64AssetDigest),
		[]byte(release.PublishedAt.UTC().Format(time.RFC3339Nano)),
	}
	for _, field := range fields {
		writeEvidenceField(hash, field)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func stringInteger(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
