package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// ReferenceCase is one `reference` case: the text of an image reference.
type ReferenceCase struct {
	Input string `json:"input"`
}

// Named is a parsed reference as JSON.
type Named struct {
	Reference string `json:"reference"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
}

// ReferenceResult is a Named, or the error that replaced it.
type ReferenceResult struct {
	Ok    *Named `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ReferenceAnswer is the answer to a ReferenceCase: what `ParseDockerRef`, which the CRI plugin calls, and
// `ParseNormalizedNamed` make of the text.
type ReferenceAnswer struct {
	Docker     ReferenceResult `json:"docker"`
	Normalized ReferenceResult `json:"normalized"`
}

func referenceResult(named reference.Named, err error) ReferenceResult {
	if err != nil {
		return ReferenceResult{Error: err.Error()}
	}
	out := &Named{
		Reference: named.String(),
		Name:      named.Name(),
		Domain:    reference.Domain(named),
		Path:      reference.Path(named),
	}
	if tagged, ok := named.(reference.Tagged); ok {
		out.Tag = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		out.Digest = digested.Digest().String()
	}
	return ReferenceResult{Ok: out}
}

func referenceCase(line []byte) (any, error) {
	var c ReferenceCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	docker, dockerErr := reference.ParseDockerRef(c.Input)
	normalized, normalizedErr := reference.ParseNormalizedNamed(c.Input)
	return ReferenceAnswer{
		Docker:     referenceResult(docker, dockerErr),
		Normalized: referenceResult(normalized, normalizedErr),
	}, nil
}

// Plat is a platform as JSON.
type Plat struct {
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Variant      string   `json:"variant"`
	OSVersion    string   `json:"os_version"`
	OSFeatures   []string `json:"os_features"`
}

func (p Plat) spec() specs.Platform {
	return specs.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant, OSVersion: p.OSVersion, OSFeatures: p.OSFeatures}
}

func plat(p specs.Platform) *Plat {
	features := p.OSFeatures
	if features == nil {
		features = []string{}
	}
	return &Plat{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant, OSVersion: p.OSVersion, OSFeatures: features}
}

// PlatformCase is one `platform` case. A Specifier is parsed. A Platform is normalized and formatted, and matched
// against the Candidates by `Only` and `OnlyStrict`, and picks the image of Index, whose blobs are Blobs, as
// containerd picks it for that platform. Host asks for the platform of the oracle itself.
type PlatformCase struct {
	Host       bool    `json:"host"`
	Specifier  *string `json:"specifier"`
	Platform   *Plat   `json:"platform"`
	Candidates []Plat  `json:"candidates"`
	Index      *Blob   `json:"index"`
	Blobs      []Blob  `json:"blobs"`
}

// Blob is a blob of a content store, with the media type its descriptor gives it.
type Blob struct {
	MediaType string `json:"media_type"`
	Content   string `json:"content"`
}

func (b Blob) descriptor() specs.Descriptor {
	return specs.Descriptor{MediaType: b.MediaType, Digest: digest.FromString(b.Content), Size: int64(len(b.Content))}
}

// Pick is the config digest of the image manifest containerd picks, or why it picks none.
type Pick struct {
	Config string `json:"config,omitempty"`
	Error  string `json:"error,omitempty"`
}

// memory is a content store of blobs by digest.
type memory map[digest.Digest][]byte

func (m memory) ReaderAt(_ context.Context, desc specs.Descriptor) (content.ReaderAt, error) {
	blob, ok := m[desc.Digest]
	if !ok {
		return nil, fmt.Errorf("blob %s not found", desc.Digest)
	}
	return readerAt{bytes.NewReader(blob)}, nil
}

type readerAt struct{ *bytes.Reader }

func (readerAt) Close() error { return nil }

// pick is the manifest the CRI image service reads an image's config from: `images.Manifest` with the matcher of
// the node's platform (v2.4.2 core/images/image.go:153).
func pick(platform specs.Platform, index Blob, blobs []Blob) *Pick {
	store := memory{}
	for _, blob := range append(blobs, index) {
		store[blob.descriptor().Digest] = []byte(blob.Content)
	}
	manifest, err := images.Manifest(context.Background(), store, index.descriptor(), platforms.Only(platform))
	if err != nil {
		return &Pick{Error: err.Error()}
	}
	return &Pick{Config: manifest.Config.Digest.String()}
}

// Matching is what a matcher says of the candidates: which match, and for each pair whether the first is less.
type Matching struct {
	Matches []bool   `json:"matches"`
	Less    [][]bool `json:"less"`
}

// PlatformAnswer is the answer to a PlatformCase.
type PlatformAnswer struct {
	Host       *Plat     `json:"host,omitempty"`
	Parsed     *Plat     `json:"parsed,omitempty"`
	ParseError string    `json:"parse_error,omitempty"`
	Normalized *Plat     `json:"normalized,omitempty"`
	Format     string    `json:"format,omitempty"`
	FormatAll  string    `json:"format_all,omitempty"`
	Only       *Matching `json:"only,omitempty"`
	OnlyStrict *Matching `json:"only_strict,omitempty"`
	Pick       *Pick     `json:"pick,omitempty"`
}

func matching(m platforms.MatchComparer, candidates []specs.Platform) *Matching {
	out := &Matching{Matches: []bool{}, Less: [][]bool{}}
	for _, a := range candidates {
		out.Matches = append(out.Matches, m.Match(a))
		row := []bool{}
		for _, b := range candidates {
			row = append(row, m.Less(a, b))
		}
		out.Less = append(out.Less, row)
	}
	return out
}

func platformCase(line []byte) (any, error) {
	var c PlatformCase
	if err := json.Unmarshal(line, &c); err != nil {
		return nil, err
	}
	var answer PlatformAnswer
	if c.Host {
		answer.Host = &Plat{OS: runtime.GOOS, Architecture: runtime.GOARCH, OSFeatures: []string{}}
	}
	if c.Specifier != nil {
		parsed, err := platforms.Parse(*c.Specifier)
		if err != nil {
			answer.ParseError = err.Error()
		} else {
			answer.Parsed = plat(parsed)
			answer.Format = platforms.Format(parsed)
			answer.FormatAll = platforms.FormatAll(parsed)
		}
	}
	if c.Platform != nil {
		p := c.Platform.spec()
		answer.Normalized = plat(platforms.Normalize(p))
		answer.Format = platforms.Format(p)
		answer.FormatAll = platforms.FormatAll(p)
		var candidates []specs.Platform
		for _, candidate := range c.Candidates {
			candidates = append(candidates, candidate.spec())
		}
		answer.Only = matching(platforms.Only(p), candidates)
		answer.OnlyStrict = matching(platforms.OnlyStrict(p), candidates)
		if c.Index != nil {
			answer.Pick = pick(p, *c.Index, c.Blobs)
		}
	}
	return answer, nil
}
