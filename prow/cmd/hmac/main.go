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
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"k8s.io/test-infra/pkg/flagutil"
	"k8s.io/test-infra/prow/cmd/hmac/updater"
	"k8s.io/test-infra/prow/config"
	prowflagutil "k8s.io/test-infra/prow/flagutil"
	"k8s.io/test-infra/prow/github"
	"k8s.io/test-infra/prow/logrusutil"
)

type options struct {
	configPath string

	dryRun     bool
	github     prowflagutil.GitHubOptions
	kubernetes prowflagutil.KubernetesOptions

	hookUrl             string
	namespace           string
	hmacTokenSecretName string
	hmacTokenKey        string
}

func (o *options) Validate() error {
	for _, group := range []flagutil.OptionGroup{&o.kubernetes, &o.github} {
		if err := group.Validate(o.dryRun); err != nil {
			return err
		}
	}

	return nil
}

func gatherOptions(fs *flag.FlagSet, args ...string) options {
	var o options

	o.github.AddFlags(fs)
	o.kubernetes.AddFlags(fs)

	fs.StringVar(&o.configPath, "config-path", "", "Path to config.yaml.")
	fs.BoolVar(&o.dryRun, "dry-run", true, "Dry run for testing. Uses API tokens but does not mutate.")

	fs.StringVar(&o.hookUrl, "hook-url", "", "Prow hook url for creating/updating github webhooks.")
	fs.StringVar(&o.namespace, "namespace", "default", "Name of the namespace on the cluster where the hmac-token secret is in.")
	fs.StringVar(&o.hmacTokenSecretName, "hmac-token-secret-name", "hmac-token", "Name of the secret on the cluster containing the GitHub HMAC secret.")
	fs.StringVar(&o.hmacTokenKey, "hmac-token-key", "hmac", "Key of the hmac token in the secret.")
	fs.Parse(args)
	return o
}

type client struct {
	options options

	kubernetesClient kubernetes.Interface

	currentHmacMap map[string]github.HmacsForRepo
	newHmacConfig  config.ManagedWebhooks
}

func main() {
	logrusutil.ComponentInit()

	o := gatherOptions(flag.NewFlagSet(os.Args[0], flag.ExitOnError), os.Args[1:]...)
	if err := o.Validate(); err != nil {
		logrus.WithError(err).Fatal("Invalid options")
	}

	kc, err := o.kubernetes.InfrastructureClusterClient(o.dryRun)
	if err != nil {
		logrus.WithError(err).Fatal("Error creating Kubernetes client for infrastructure cluster.")
	}

	currentHmacYaml, err := getCurrentHmacTokens(kc, o.namespace, o.hmacTokenSecretName, o.hmacTokenKey)
	if err != nil {
		logrus.WithError(err).Fatal("Error getting the current hmac yaml.")
	}

	currentHmacMap := map[string]github.HmacsForRepo{}
	if err := yaml.Unmarshal(currentHmacYaml, &currentHmacMap); err != nil {
		logrus.WithError(err).Fatal("Couldn't unmarshal the hmac secret as hierarchical file.")
	}
	configAgent := &config.Agent{}
	if err := configAgent.Start(o.configPath, ""); err != nil {
		logrus.WithError(err).Fatal("Error starting config agent.")
	}
	newHmacConfig := configAgent.Config().ManagedWebhooks

	c := &client{
		kubernetesClient: kc,
		options:          o,

		currentHmacMap: currentHmacMap,
		newHmacConfig:  newHmacConfig,
	}

	if err := c.handleConfigUpdate(); err != nil {
		logrus.WithError(err).Fatal("Error handling hmac config update.")
	}
}

func (c *client) handleConfigUpdate() error {
	repoAdded := map[string]config.ManagedWebhookInfo{}
	repoRemoved := map[string]bool{}
	repoRotated := map[string]config.ManagedWebhookInfo{}

	for repoName, hmacConfig := range c.newHmacConfig {
		if _, ok := c.currentHmacMap[repoName]; ok {
			repoRotated[repoName] = hmacConfig
		} else {
			repoAdded[repoName] = hmacConfig
		}
	}

	for repoName := range c.currentHmacMap {
		if _, ok := c.newHmacConfig[repoName]; !ok {
			repoRemoved[repoName] = true
		}
	}

	if err := c.handleRemovedRepo(repoRemoved); err != nil {
		return fmt.Errorf("error handling hmac update for removed repos: %v", err)
	}
	if err := c.handleAddedRepo(repoAdded); err != nil {
		return fmt.Errorf("error handling hmac update for new repos: %v", err)
	}
	if err := c.handledRotatedRepo(repoRotated); err != nil {
		return fmt.Errorf("error handling hmac rotations for the repos: %v", err)
	}

	// Update the secret
	if err := c.updateHmacTokens(); err != nil {
		return fmt.Errorf("error updating hmac tokens: %v", err)
	}

	return nil
}

// handleRemoveRepo handles webhook removal and hmac token removal from k8s cluster for all repos removed from the declarative config.
func (c *client) handleRemovedRepo(removed map[string]bool) error {
	repos := make([]string, len(removed))
	i := 0
	for k := range removed {
		repos[i] = k
		i++
	}

	o := &updater.Options{
		GitHubOptions: c.options.github,
		Repos:         prowflagutil.NewStrings(repos...),
		ShouldDelete:  true,
		Confirm:       true,
	}

	if err := updater.HandleWebhookConfigChange(o); err != nil {
		return fmt.Errorf("error deleting webhook for repos %q: %v", repos, err)
	}
	for _, repo := range repos {
		delete(c.currentHmacMap, repo)
	}
	// No need to update the secret here, the following update will commit the changes together.

	return nil
}

func (c *client) handleAddedRepo(added map[string]config.ManagedWebhookInfo) error {
	for repo := range added {
		if err := c.onboardNewTokenForSingleRepo(repo); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) handledRotatedRepo(rotated map[string]config.ManagedWebhookInfo) error {
	// For each rotated repo, we only onboard a new token when none of the existing tokens is created after user specified time.
	for repo, hmacConfig := range rotated {
		needsRotation := true
		for _, token := range c.currentHmacMap[repo] {
			// If the existing token is created after the user specified time, we do not need to rotate it.
			if token.CreatedAt.After(hmacConfig.TokenCreatedAfter) {
				needsRotation = false
				break
			}
		}
		if needsRotation {
			if err := c.onboardNewTokenForSingleRepo(repo); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *client) onboardNewTokenForSingleRepo(repo string) error {
	generatedToken, err := generateNewHmacToken()
	if err != nil {
		return fmt.Errorf("error generating a new hmac token for repo %q: %v", repo, err)
	}

	updatedTokenList := github.HmacsForRepo{}
	orgName := strings.Split(repo, "/")[0]
	if val, ok := c.currentHmacMap[repo]; ok {
		// Copy over all existing tokens for that repo.
		updatedTokenList = append(updatedTokenList, val...)
	} else if val, ok := c.currentHmacMap[orgName]; ok {
		// Current webhook is using org lvl token. So we need to promote that token to repo level as well.
		updatedTokenList = append(updatedTokenList, val...)
	} else {
		// Current webhook is possibly using global token so we need to promote that token to repo level as well.
		globalTokens := c.currentHmacMap["*"]
		updatedTokenList = append(updatedTokenList, globalTokens...)
	}

	updatedTokenList = append(updatedTokenList, github.HmacSecret{
		Value: generatedToken, CreatedAt: time.Now()})
	c.currentHmacMap[repo] = updatedTokenList

	// Update the hmac tokens first, to guarantee the new token is available to hook.
	if err := c.updateHmacTokens(); err != nil {
		return fmt.Errorf("error updating hmac tokens: %v", err)
	}

	// HACK: sleep 20 seconds to wait for the reconciliation to finish.
	time.Sleep(20 * time.Second)

	// Update the github webhook to use new token.
	o := &updater.Options{
		GitHubOptions: c.options.github,
		Repos:         prowflagutil.NewStrings(repo),
		HookURL:       c.options.hookUrl,
		HmacValue:     generatedToken,
		// Receive hooks for all the events.
		Events:       prowflagutil.NewStrings(github.AllHookEvents...),
		ShouldDelete: true,
		Confirm:      true,
	}

	if err := updater.HandleWebhookConfigChange(o); err != nil {
		// Log and skip to next one.
		return fmt.Errorf("error updating webhook for repo %q: %v", repo, err)
	}

	// Remove old token from current config.
	c.pruneOldTokens(repo)

	// No need to update the secret here, the following update will commit the changes together.
	return nil
}

// updateHmacTokens saves given in-memory config to secret file used by prow cluster.
func (c *client) updateHmacTokens() error {
	secretContent, err := yaml.Marshal(&c.currentHmacMap)
	if err != nil {
		return fmt.Errorf("error converting hmac map to yaml: %v", err)
	}
	secret := &corev1.Secret{}
	secret.Name = c.options.hmacTokenSecretName
	secret.Namespace = c.options.namespace
	secret.StringData = map[string]string{c.options.hmacTokenKey: string(secretContent)}
	if _, err = c.kubernetesClient.CoreV1().Secrets(c.options.namespace).Update(secret); err != nil {
		return fmt.Errorf("error updating the secret: %v", err)
	}
	return nil
}

// pruneOldTokens removes all but most recent token from token config.
func (c *client) pruneOldTokens(repo string) {
	tokens := c.currentHmacMap[repo]
	if len(tokens) <= 1 {
		logrus.Debugf("Token size for repo %q is %d, no need to prune", repo, len(tokens))
		return
	}

	sort.SliceStable(tokens, func(i, j int) bool {
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})
	c.currentHmacMap[repo] = tokens[:1]
}

// generateNewHmacToken generates a hex encoded crypto random string of length 20.
func generateNewHmacToken() (string, error) {
	bytes := make([]byte, 20) // our hmac token are of length 20
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// getCurrentHmacTokens returns the hmac tokens currently configured in the cluster.
func getCurrentHmacTokens(kc kubernetes.Interface, ns, secName, key string) ([]byte, error) {
	secret, err := kc.CoreV1().Secrets(ns).Get(secName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("error getting hmac secret %q: %v", secName, err)
	}
	if err == nil {
		buf, ok := secret.Data[key]
		if ok {
			return buf, nil
		}
	}
	return nil, fmt.Errorf("error getting hmac token values: %v", err)
}
