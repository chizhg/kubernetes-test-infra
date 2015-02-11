/*
Copyright 2014 Google Inc. All rights reserved.

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

// e2e.go runs the e2e test suite. No non-standard package dependencies; call with "go run".
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	isup             = flag.Bool("isup", false, "Check to see if the e2e cluster is up, then exit.")
	build            = flag.Bool("build", false, "If true, build a new release. Otherwise, use whatever is there.")
	version          = flag.String("version", "", "The version to be tested (including the leading 'v'). An empty string defaults to the local build, but it can be set to any release (e.g. v0.4.4, v0.6.0).")
	up               = flag.Bool("up", false, "If true, start the the e2e cluster. If cluster is already up, recreate it.")
	push             = flag.Bool("push", false, "If true, push to e2e cluster. Has no effect if -up is true.")
	pushup           = flag.Bool("pushup", false, "If true, push to e2e cluster if it's up, otherwise start the e2e cluster.")
	down             = flag.Bool("down", false, "If true, tear down the cluster before exiting.")
	test             = flag.Bool("test", false, "Run Ginkgo tests.")
	root             = flag.String("root", absOrDie(filepath.Clean(filepath.Join(path.Base(os.Args[0]), ".."))), "Root directory of kubernetes repository.")
	verbose          = flag.Bool("v", false, "If true, print all command output.")
	checkVersionSkew = flag.Bool("check_version_skew", true, ""+
		"By default, verify that client and server have exact version match. "+
		"You can explicitly set to false if you're, e.g., testing client changes "+
		"for which the server version doesn't make a difference.")

	ctlCmd = flag.String("ctl", "", "If nonempty, pass this as an argument, and call kubectl. Implies -v. (-test, -cfg, -ctl are mutually exclusive)")
)

const (
	serverTarName   = "kubernetes-server-linux-amd64.tar.gz"
	saltTarName     = "kubernetes-salt.tar.gz"
	downloadDirName = "_output/downloads"
	tarDirName      = "server"
	tempDirName     = "upgrade-e2e-temp-dir"
	minMinionCount  = 2
)

var (
	signals = make(chan os.Signal, 100)
	// Root directory of the specified cluster version, rather than of where
	// this script is being run from.
	versionRoot = *root
)

func absOrDie(path string) string {
	out, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return out
}

type TestResult struct {
	Pass int
	Fail int
}

type ResultsByTest map[string]TestResult

func main() {
	flag.Parse()
	signal.Notify(signals, os.Interrupt)

	if *isup {
		status := 1
		if IsUp() {
			status = 0
			log.Printf("Cluster is UP")
		} else {
			log.Printf("Cluster is DOWN")
		}
		os.Exit(status)
	}

	if *build {
		// The build-release script needs stdin to ask the user whether
		// it's OK to download the docker image.
		cmd := exec.Command(path.Join(*root, "hack/e2e-internal/build-release.sh"))
		cmd.Stdin = os.Stdin
		if !finishRunning("build-release", cmd) {
			log.Fatal("Error building. Aborting.")
		}
	}

	if *version != "" {
		// If the desired version isn't available already, do whatever's needed
		// to make it available. Once done, update the root directory for client
		// tools to be the root of the release directory so that the given
		// release's tools will be used. We can't use this new root for
		// everything because it likely doesn't have the hack/ directory in it.
		if newVersionRoot, err := PrepareVersion(*version); err != nil {
			log.Fatalf("Error preparing a binary of version %s: %s. Aborting.", *version, err)
		} else {
			versionRoot = newVersionRoot
			os.Setenv("KUBE_VERSION_ROOT", newVersionRoot)
		}
	}

	os.Setenv("KUBECTL", versionRoot+`/cluster/kubectl.sh`+kubectlArgs())

	if *pushup {
		if IsUp() {
			log.Printf("e2e cluster is up, pushing.")
			*up = false
			*push = true
		} else {
			log.Printf("e2e cluster is down, creating.")
			*up = true
			*push = false
		}
	}
	if *up {
		if !Up() {
			log.Fatal("Error starting e2e cluster. Aborting.")
		}
	} else if *push {
		if !finishRunning("push", exec.Command(path.Join(*root, "hack/e2e-internal/e2e-push.sh"))) {
			log.Fatal("Error pushing e2e cluster. Aborting.")
		}
	}

	failure := false
	switch {
	case *ctlCmd != "":
		ctlArgs := strings.Fields(*ctlCmd)
		os.Setenv("KUBE_CONFIG_FILE", "config-test.sh")
		failure = !finishRunning("'kubectl "+*ctlCmd+"'", exec.Command(path.Join(versionRoot, "cluster/kubectl.sh"), ctlArgs...))
	case *test:
		failure = Test()
	}

	if *down {
		TearDown()
	}

	if failure {
		os.Exit(1)
	}
}

func TearDown() bool {
	return finishRunning("teardown", exec.Command(path.Join(*root, "hack/e2e-internal/e2e-down.sh")))
}

// Up brings an e2e cluster up, recreating it if one is already running.
func Up() bool {
	if IsUp() {
		log.Printf("e2e cluster already running; will teardown")
		if res := TearDown(); !res {
			return false
		}
	}

	return finishRunning("up", exec.Command(path.Join(*root, "hack/e2e-internal/e2e-up.sh")))
}

// Ensure that the cluster is large engough to run the e2e tests.
func ValidateClusterSize() {
	// Check that there are at least 3 minions running
	res, stdout, _ := finishRunningWithOutputs("validate cluster size", exec.Command(path.Join(*root, "hack/e2e-internal/e2e-cluster-size.sh")))
	if !res {
		log.Fatal("Could not get nodes to validate cluster size")
	}

	numNodes, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		log.Fatalf("Could not count number of nodes to validate cluster size (%s)", err)
	}

	if numNodes < minMinionCount {
		log.Fatalf("Cluster size (%d) is too small to run e2e tests.  %d Minions are required.", numNodes, minMinionCount)
	}
}

// Is the e2e cluster up?
func IsUp() bool {
	return finishRunning("get status", exec.Command(path.Join(*root, "hack/e2e-internal/e2e-status.sh")))
}

// PrepareVersion makes sure that the specified release version is locally
// available and ready to be used by kube-up or kube-push. Returns the director
// path of the release.
func PrepareVersion(version string) (string, error) {
	if version == "" {
		// Assume that the build flag already handled building a local binary.
		return *root, nil
	}

	// If the version isn't a local build, try fetching the release from Google
	// Cloud Storage.
	downloadDir := filepath.Join(*root, downloadDirName)
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return "", err
	}
	localReleaseDir := filepath.Join(downloadDir, version)
	if err := os.MkdirAll(localReleaseDir, 0755); err != nil {
		return "", err
	}

	remoteReleaseTar := fmt.Sprintf("https://storage.googleapis.com/kubernetes-release/release/%s/kubernetes.tar.gz", version)
	localReleaseTar := filepath.Join(downloadDir, fmt.Sprintf("kubernetes-%s.tar.gz", version))
	if _, err := os.Stat(localReleaseTar); os.IsNotExist(err) {
		out, err := os.Create(localReleaseTar)
		if err != nil {
			return "", err
		}
		resp, err := http.Get(remoteReleaseTar)
		if err != nil {
			out.Close()
			return "", err
		}
		defer resp.Body.Close()
		io.Copy(out, resp.Body)
		if err != nil {
			out.Close()
			return "", err
		}
		out.Close()
	}
	if !finishRunning("untarRelease", exec.Command("tar", "-C", localReleaseDir, "-zxf", localReleaseTar, "--strip-components=1")) {
		log.Fatal("Failed to untar release. Aborting.")
	}
	// Now that we have the binaries saved locally, use the path to the untarred
	// directory as the "root" path for future operations.
	return localReleaseDir, nil
}

// Fisher-Yates shuffle using the given RNG r
func shuffleStrings(strings []string, r *rand.Rand) {
	for i := len(strings) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		strings[i], strings[j] = strings[j], strings[i]
	}
}

func Test() bool {
	defer runBashUntil("watchEvents", exec.Command(filepath.Join(*root, "hack/e2e-internal/e2e-watch-events.sh")))()

	if !IsUp() {
		log.Fatal("Testing requested, but e2e cluster not up!")
	}

	ValidateClusterSize()

	return finishRunning("Ginkgo tests", exec.Command(filepath.Join(*root, "hack/ginkgo-e2e.sh")))
}

// All nonsense below is temporary until we have go versions of these things.

// call the returned anonymous function to stop.
func runBashUntil(stepName string, cmd *exec.Cmd) func() {
	log.Printf("Running in background: %v", stepName)
	stdout, stderr := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		log.Printf("Unable to start '%v': '%v'", stepName, err)
		return func() {}
	}
	return func() {
		cmd.Process.Signal(os.Interrupt)
		headerprefix := stepName + " "
		lineprefix := "  "
		printBashOutputs(headerprefix, lineprefix, string(stdout.Bytes()), string(stderr.Bytes()), false)
	}
}

func finishRunningWithOutputs(stepName string, cmd *exec.Cmd) (bool, string, string) {
	log.Printf("Running: %v", stepName)
	stdout, stderr := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	if *verbose {
		cmd.Stdout = io.MultiWriter(os.Stdout, stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, stderr)
	} else {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case s := <-signals:
				cmd.Process.Signal(s)
			}
		}
	}()

	if err := cmd.Run(); err != nil {
		log.Printf("Error running %v: %v", stepName, err)
		return false, string(stdout.Bytes()), string(stderr.Bytes())
	}
	return true, string(stdout.Bytes()), string(stderr.Bytes())
}

func finishRunning(stepName string, cmd *exec.Cmd) bool {
	result, _, _ := finishRunningWithOutputs(stepName, cmd)
	return result
}

func printBashOutputs(headerprefix, lineprefix, stdout, stderr string, escape bool) {
	// The |'s (plus appropriate prefixing) are to make this look
	// "YAMLish" to the Jenkins TAP plugin:
	//   https://wiki.jenkins-ci.org/display/JENKINS/TAP+Plugin
	if stdout != "" {
		fmt.Printf("%vstdout: |\n", headerprefix)
		if escape {
			stdout = escapeOutput(stdout)
		}
		printPrefixedLines(lineprefix, stdout)
	}
	if stderr != "" {
		fmt.Printf("%vstderr: |\n", headerprefix)
		if escape {
			stderr = escapeOutput(stderr)
		}
		printPrefixedLines(lineprefix, stderr)
	}
}

// Escape stdout/stderr so the Jenkins YAMLish parser doesn't barf on
// it. This escaping is crude (it masks all colons as something humans
// will hopefully see as a colon, for instance), but it should get the
// job done without pulling in a whole YAML package.
func escapeOutput(s string) (out string) {
	for _, r := range s {
		switch {
		case r == '\n':
			out += string(r)
		case !strconv.IsPrint(r):
			out += " "
		case r == ':':
			out += "\ua789" // "꞉", modifier letter colon
		default:
			out += string(r)
		}
	}
	return
}

func printPrefixedLines(prefix, s string) {
	for _, line := range strings.Split(s, "\n") {
		fmt.Printf("%v%v\n", prefix, line)
	}
}

// returns either "", or a list of args intended for appending with the
// kubectl command (begining with a space).
func kubectlArgs() string {
	if *checkVersionSkew {
		return " --match-server-version"
	}
	return ""
}
