/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"k8s.io/test-infra/prow/flagutil"
	"k8s.io/test-infra/prow/github"
)

func TestGatherOptions(t *testing.T) {
	cases := []struct {
		name     string
		args     map[string]string
		del      sets.String
		expected func(*options)
		err      bool
	}{
		{
			name: "minimal flags work",
		},
		{
			name: "explicitly set --config-path",
			args: map[string]string{
				"--config-path": "/random/value",
			},
			expected: func(o *options) {
				o.configPath = "/random/value"
			},
		},
		{
			name: "expicitly set --dry-run=false",
			args: map[string]string{
				"--dry-run": "false",
			},
			expected: func(o *options) {
				o.dryRun = false
			},
		},
		{
			name: "--dry-run=true requires --deck-url",
			args: map[string]string{
				"--dry-run":  "true",
				"--deck-url": "",
			},
			err: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ghoptions := flagutil.GitHubOptions{}
			ghoptions.AddFlags(&flag.FlagSet{})
			ghoptions.Validate(false)
			expected := &options{
				configPath:          "yo",
				dryRun:              true,
				github:              ghoptions,
				kubernetes:          flagutil.KubernetesOptions{DeckURI: "http://whatever"},
				namespace:           "default",
				hmacTokenSecretName: "hmac-token",
				hmacTokenKey:        "hmac",
			}
			if tc.expected != nil {
				tc.expected(expected)
			}

			argMap := map[string]string{
				"--config-path": "yo",
				"--deck-url":    "http://whatever",
			}
			for k, v := range tc.args {
				argMap[k] = v
			}
			for k := range tc.del {
				delete(argMap, k)
			}

			var args []string
			for k, v := range argMap {
				args = append(args, k+"="+v)
			}
			fs := flag.NewFlagSet("fake-flags", flag.PanicOnError)
			actual := gatherOptions(fs, args...)
			switch err := actual.Validate(); {
			case err != nil:
				if !tc.err {
					t.Errorf("unexpected error: %v", err)
				}
			case tc.err:
				t.Errorf("failed to receive expected error")
			case !reflect.DeepEqual(*expected, actual):
				t.Errorf("%#v != expected %#v", actual, *expected)
			}
		})
	}
}

func TestPruneOldTokens(t *testing.T) {
	// "2006-01-02T15:04:05+07:00"
	time1, _ := time.Parse(time.RFC3339, "2020-01-05T19:07:08+00:00")
	time2, _ := time.Parse(time.RFC3339, "2020-02-05T19:07:08+00:00")
	time3, _ := time.Parse(time.RFC3339, "2020-03-05T19:07:08+00:00")

	cases := []struct {
		name     string
		current  map[string]github.HmacsForRepo
		repo     string
		expected map[string]github.HmacsForRepo
	}{
		{
			name: "three hmacs, only the latest one is left after pruning",
			current: map[string]github.HmacsForRepo{
				"org1/repo1": []github.HmacSecret{
					{
						Value:     "rand-val1",
						CreatedAt: time1,
					},
					{
						Value:     "rand-val2",
						CreatedAt: time2,
					},
					{
						Value:     "rand-val3",
						CreatedAt: time3,
					},
				},
			},
			repo: "org1/repo1",
			expected: map[string]github.HmacsForRepo{
				"org1/repo1": []github.HmacSecret{
					{
						Value:     "rand-val3",
						CreatedAt: time3,
					},
				},
			},
		},
		{
			name: "two hmacs, only the latest one is left after pruning",
			current: map[string]github.HmacsForRepo{
				"org1/repo1": []github.HmacSecret{
					{
						Value:     "rand-val1",
						CreatedAt: time1,
					},
					{
						Value:     "rand-val2",
						CreatedAt: time2,
					},
				},
			},
			repo: "org1/repo1",
			expected: map[string]github.HmacsForRepo{
				"org1/repo1": []github.HmacSecret{
					{
						Value:     "rand-val2",
						CreatedAt: time2,
					},
				},
			},
		},
		{
			name: "nothing will be changed if the repo is not in the map",
			current: map[string]github.HmacsForRepo{
				"org1/repo1": []github.HmacSecret{
					{
						Value:     "rand-val1",
						CreatedAt: time1,
					},
				},
			},
			repo: "org2/repo2",
			expected: map[string]github.HmacsForRepo{
				"org1/repo1": []github.HmacSecret{
					{
						Value:     "rand-val1",
						CreatedAt: time1,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &client{currentHmacMap: tc.current}
			c.pruneOldTokens(tc.repo)
			if !reflect.DeepEqual(tc.expected, c.currentHmacMap) {
				t.Errorf("%#v != expected %#v", c.currentHmacMap, tc.expected)
			}
		})
	}
}

func TestGenerateNewHmacToken(t *testing.T) {
	token1, err := generateNewHmacToken()
	if err != nil {
		t.Errorf("error generating new hmac token1: %v", err)
	}

	token2, err := generateNewHmacToken()
	if err != nil {
		t.Errorf("error generating new hmac token2: %v", err)
	}
	if token1 == token2 {
		t.Error("the generated hmac token should be random, but the two are equal")
	}
}
