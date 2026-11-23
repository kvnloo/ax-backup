// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package substrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/ax/internal/install/executil"
)

func TestEmbeddedManifestsMatchGoModVersion(t *testing.T) {
	goModBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*go\.ate\.dev/substrate\s+(\S+)`)
	m := re.FindSubmatch(goModBytes)
	if len(m) < 2 {
		t.Fatalf("could not find go.ate.dev/substrate in go.mod")
	}
	want := string(m[1])
	got := EmbeddedVersion()
	if got != want {
		t.Fatalf("embedded Substrate manifests version = %q, go.mod wants %q; run ./hack/sync-substrate-manifests.sh", got, want)
	}
}

func TestEmbeddedManifestsContainNoUnresolvedPlaceholders(t *testing.T) {
	entries, err := embeddedManifests.ReadDir("manifests")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	yamlCount := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		yamlCount++
		raw, err := embeddedManifests.ReadFile("manifests/" + e.Name())
		if err != nil {
			t.Fatalf("ReadFile %s: %v", e.Name(), err)
		}
		s := string(raw)
		for _, bad := range []string{"ko://go.ate.dev/substrate", "${ENVOY_DATAPLANE_IMAGE}", "#ATE_EGRESS_INJECT_FLAGS"} {
			if strings.Contains(s, bad) {
				t.Fatalf("manifest %s still contains unresolved %q", e.Name(), bad)
			}
		}
	}
	if yamlCount != 8 {
		t.Fatalf("expected 8 embedded YAML bundles, got %d", yamlCount)
	}
}

func TestLocalRegistryEndpoint(t *testing.T) {
	// The embedded manifests name the registry as <host>:<port>.
	endpoint, err := LocalRegistryEndpoint()
	if err != nil {
		t.Fatalf("LocalRegistryEndpoint: %v", err)
	}
	if host, port, err := net.SplitHostPort(endpoint); err != nil || host == "" || port == "" {
		t.Fatalf("LocalRegistryEndpoint() = %q, want <host>:<port> (error: %v)", endpoint, err)
	}

	manifest := func(daemonSet string, args ...string) []byte {
		var b strings.Builder
		fmt.Fprintf(&b, "kind: Deployment\nmetadata:\n  name: atelet\n---\nkind: DaemonSet\nmetadata:\n  name: %s\n", daemonSet)
		b.WriteString("spec:\n  template:\n    spec:\n      containers:\n      - name: atelet\n        args:\n")
		for _, arg := range args {
			fmt.Fprintf(&b, "        - %s\n", arg)
		}
		return []byte(b.String())
	}
	for _, tc := range []struct {
		name     string
		manifest []byte
		want     string
	}{
		{name: "flag set", manifest: manifest("atelet", "--log-level=debug", "--localhost-registry-replacement=my-registry:5000"), want: "my-registry:5000"},
		{name: "flag not set", manifest: manifest("atelet", "--log-level=debug")},
		{name: "flag on another DaemonSet", manifest: manifest("other", "--localhost-registry-replacement=my-registry:5000")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := localRegistryEndpoint(tc.manifest)
			if err != nil || got != tc.want {
				t.Errorf("localRegistryEndpoint() = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestRenderSystemBundleStampsAuthzAndEnvHash(t *testing.T) {
	raw, err := embeddedManifests.ReadFile("manifests/05-ate-system.yaml")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	rendered, err := RenderSystemBundle(raw, "deadbeef1234", "ax-custom")
	if err != nil {
		t.Fatalf("RenderSystemBundle: %v", err)
	}
	s := string(rendered)
	for _, want := range []string{
		"ate.dev/env-hash: deadbeef1234",
		"--authz-bootstrap-owners=system:serviceaccount:ate-system:ate-client,system:serviceaccount:ax-custom:ax-server",
		"--ingress-allowed-spiffe-ids=spiffe://cluster.local/ns/ax-custom/sa/ax-server",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %q in rendered system bundle", want)
		}
	}
	if strings.Contains(s, "replicas: 2") {
		t.Fatalf("expected local system bundle to scale multi-replica control-plane Deployments down to 1 replica")
	}
}

// funcRunner fakes kubectl with a function, and records the commands.
type funcRunner struct {
	calls []string
	run   func(cmd string) (executil.Result, error)
}

func (f *funcRunner) LookPath(file string) (string, error) { return "/usr/bin/" + file, nil }

func (f *funcRunner) Run(_ context.Context, spec executil.Spec) (executil.Result, error) {
	cmd := strings.Join(spec.Args, " ")
	f.calls = append(f.calls, cmd)
	return f.run(cmd)
}

// testNow is the time of the tests of stuck pods.
var testNow = time.Date(2026, 11, 21, 22, 35, 0, 0, time.UTC)

// testPod returns the JSON of a pod of the Deployment app with two
// containers. "main" is running and ready. "envoy" has been running since
// started, in the state the test names. The pod's containers have not all
// been ready since unready.
func testPod(app, envoy string, started, unready time.Time, extraMetadata string) string {
	state := fmt.Sprintf(`"ready":false,"state":{"running":{"startedAt":%q}}`, started.Format(time.RFC3339))
	switch envoy {
	case "ready":
		state = fmt.Sprintf(`"ready":true,"state":{"running":{"startedAt":%q}}`, started.Format(time.RFC3339))
	case "waiting":
		state = `"ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}`
	}
	condition := "False"
	if envoy == "ready" {
		condition = "True"
	}
	return fmt.Sprintf(`{"metadata":{"name":"%s-abc","labels":{"app":%q}%s},"status":{"phase":"Running",`+
		`"conditions":[{"type":"ContainersReady","status":%q,"lastTransitionTime":%q}],`+
		`"containerStatuses":[{"name":"main","ready":true,"state":{"running":{"startedAt":%q}}},{"name":"envoy",%s}]}}`,
		app, app, extraMetadata, condition, unready.Format(time.RFC3339), started.Format(time.RFC3339), state)
}

// https://github.com/google/ax/issues/697: only the router container of
// atenet-router restarted, and its envoy container, which kept running, was
// not ready for 16 hours.
func TestStuckContainer(t *testing.T) {
	longAgo := testNow.Add(-40 * time.Hour)
	sixteenHours := testNow.Add(-16 * time.Hour)
	cases := []struct {
		name      string
		pod       string
		wantStuck bool
		wantFor   time.Duration
	}{
		{name: "running and unready for 16 hours", pod: testPod("atenet-router", "unready", longAgo, sixteenHours, ""), wantStuck: true, wantFor: 16 * time.Hour},
		{name: "unready for exactly the threshold", pod: testPod("atenet-router", "unready", longAgo, testNow.Add(-stuckThreshold), ""), wantStuck: true, wantFor: stuckThreshold},
		{name: "unready for less than the threshold", pod: testPod("atenet-router", "unready", longAgo, testNow.Add(-stuckThreshold+time.Second), "")},
		// A cluster that comes back from a restart of its node: the pod has
		// been unready since the node started, the container started just now.
		{name: "container started a moment ago", pod: testPod("atenet-router", "unready", testNow.Add(-5*time.Second), testNow.Add(-2*time.Minute), "")},
		{name: "ready", pod: testPod("atenet-router", "ready", longAgo, longAgo, "")},
		{name: "waiting, not running", pod: testPod("atenet-router", "waiting", longAgo, sixteenHours, "")},
		{name: "being deleted", pod: testPod("atenet-router", "unready", longAgo, sixteenHours, `,"deletionTimestamp":"2026-11-21T22:34:00Z"`)},
		{name: "not in phase Running", pod: strings.Replace(testPod("atenet-router", "unready", longAgo, sixteenHours, ""), `"phase":"Running"`, `"phase":"Pending"`, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pod stuckPod
			if err := json.Unmarshal([]byte(tc.pod), &pod); err != nil {
				t.Fatalf("decoding the test pod: %v", err)
			}
			container, unready, ok := stuckContainer(pod, testNow)
			if ok != tc.wantStuck {
				t.Fatalf("stuckContainer = (%q, %s, %v), want stuck = %v", container, unready, ok, tc.wantStuck)
			}
			if ok && (container != "envoy" || unready != tc.wantFor) {
				t.Errorf("stuckContainer = (%q, %s), want (envoy, %s)", container, unready, tc.wantFor)
			}
		})
	}
}

func TestRestartStuckDeployments(t *testing.T) {
	longAgo := testNow.Add(-40 * time.Hour)
	sixteenHours := testNow.Add(-16 * time.Hour)
	stuck := func(app string) string { return testPod(app, "unready", longAgo, sixteenHours, "") }
	pods := map[string][]string{
		NamespaceAteSystem: {
			stuck("atenet-router"),
			stuck("atenet-router"), // a second stuck pod of the same Deployment
			testPod("atenet-egress", "ready", longAgo, longAgo, ""),
			testPod("ate-api-server", "unready", testNow.Add(-5*time.Second), testNow.Add(-2*time.Minute), ""),
			// Stuck, but never restarted.
			stuck("postgres"),
			stuck("rustfs"),
			stuck("atelet"),
		},
		NamespacePodCert: {stuck("podcertificate-controller")},
		NamespaceWorkers: {stuck("ax-workers")},
	}
	r := &funcRunner{run: func(cmd string) (executil.Result, error) {
		for ns, items := range pods {
			if strings.Contains(cmd, "-n "+ns+" get pods") {
				return executil.Result{Stdout: `{"items":[` + strings.Join(items, ",") + `]}`}, nil
			}
		}
		return executil.Result{}, nil
	}}
	var out bytes.Buffer
	k := &kubeHelper{runner: r, kubectl: "kubectl", context: "ax-local", out: &out}
	k.restartStuckDeployments(context.Background(), testNow)

	var restarts []string
	for _, call := range r.calls {
		if strings.Contains(call, "rollout restart") {
			restarts = append(restarts, call)
		}
	}
	want := []string{
		"--context ax-local -n podcertificate-controller-system rollout restart deployment/podcertificate-controller",
		"--context ax-local -n ate-system rollout restart deployment/atenet-router",
	}
	if strings.Join(restarts, "\n") != strings.Join(want, "\n") {
		t.Errorf("restarts = %q, want %q", restarts, want)
	}
	if want := "    ate-system/deployment/atenet-router is stuck: pod atenet-router-abc, container envoy has been running but not ready for 16h0m0s. Restarting it...\n"; !strings.Contains(out.String(), want) {
		t.Errorf("output = %q, want it to contain %q", out.String(), want)
	}
}

// A cluster without Agent Substrate has no pods to restart, and a namespace
// that cannot be read is skipped.
func TestRestartStuckDeploymentsOnAnEmptyCluster(t *testing.T) {
	r := &funcRunner{run: func(cmd string) (executil.Result, error) {
		if strings.Contains(cmd, "-n "+NamespacePodCert) {
			return executil.Result{}, fmt.Errorf(`namespaces %q not found`, NamespacePodCert)
		}
		return executil.Result{Stdout: `{"items":[]}`}, nil
	}}
	k := &kubeHelper{runner: r, kubectl: "kubectl"}
	k.restartStuckDeployments(context.Background(), testNow)
	for _, call := range r.calls {
		if strings.Contains(call, "rollout restart") {
			t.Errorf("restarted on an empty cluster: %s", call)
		}
	}
}

// A container that got stuck while Bootstrap waited: the error gives the
// kubectl command, and for a Deployment that `ax local start` restarts
// itself, it also says to run `ax local start` again.
func TestRolloutStatusTimeoutSuggestsRunningAgain(t *testing.T) {
	const pods = `{"items":[{"metadata":{"name":"stuck-abc"},"status":{"phase":"Running",` +
		`"containerStatuses":[{"name":"envoy","ready":false,"state":{"running":{"startedAt":"2026-11-21T06:35:00Z"}}}]}}]}`
	cases := []struct {
		namespace, target string
		wantRunAgain      bool
	}{
		{NamespaceAteSystem, "deployment/atenet-router", true},
		{NamespaceAteSystem, "deployment/atenet-egress", true},
		{NamespaceAteSystem, "statefulset/postgres", false},
		{NamespaceAteSystem, "daemonset/atelet", false},
		{NamespaceWorkers, "deployment/ax-workers", false},
	}
	for _, tc := range cases {
		t.Run(tc.namespace+"/"+tc.target, func(t *testing.T) {
			r := &funcRunner{run: func(cmd string) (executil.Result, error) {
				switch {
				case strings.Contains(cmd, "rollout status"):
					const timedOut = "error: timed out waiting for the condition"
					return executil.Result{Stderr: timedOut}, fmt.Errorf("exit status 1 (%s)", timedOut)
				case strings.Contains(cmd, "matchLabels"):
					return executil.Result{Stdout: `{"app":"x"}`}, nil
				case strings.Contains(cmd, "get pods"):
					return executil.Result{Stdout: pods}, nil
				}
				return executil.Result{}, nil
			}}
			k := &kubeHelper{runner: r, kubectl: "kubectl", context: "ax-local"}
			err := k.rolloutStatus(context.Background(), tc.namespace, tc.target, 20*time.Millisecond)
			want := "waiting for " + tc.namespace + "/" + tc.target + " rollout: timed out after 20ms: " +
				"pod stuck-abc, container envoy: running but not ready; " +
				"to restart it, run: kubectl --context ax-local -n " + tc.namespace + " rollout restart " + tc.target
			if tc.wantRunAgain {
				want += ", or run `ax local start` again"
			}
			if err == nil || err.Error() != want {
				t.Errorf("error = %v, want %q", err, want)
			}
			for _, call := range r.calls {
				if strings.Contains(call, "rollout restart") {
					t.Errorf("rolloutStatus restarted a workload: %s", call)
				}
			}
		})
	}
}

func TestRestartableDeployments(t *testing.T) {
	for _, d := range []string{
		NamespaceAteSystem + "/postgres",
		NamespaceAteSystem + "/rustfs",
		NamespaceAteSystem + "/atelet",
		NamespaceWorkers + "/ax-workers",
	} {
		if restartableDeployments[d] {
			t.Errorf("restartableDeployments has %q, which must never be restarted", d)
		}
	}
	// Bootstrap restarts a stuck Deployment only after alreadyHealthy found
	// the cluster unhealthy, so alreadyHealthy must look at each of them.
	for d := range restartableDeployments {
		ns, name, _ := strings.Cut(d, "/")
		found := false
		for _, s := range healthSelectors {
			if s.ns == ns && s.sel == "app="+name {
				found = true
			}
		}
		if !found {
			t.Errorf("healthSelectors has no selector for %s", d)
		}
	}
}

// https://github.com/google/ax/issues/697: alreadyHealthy looked at
// atenet-router but not at atenet-egress, whose envoy container gets stuck
// the same way, and reported the cluster healthy.
func TestAlreadyHealthyRequiresEveryWorkload(t *testing.T) {
	healthy := func(unready string) bool {
		r := &funcRunner{run: func(cmd string) (executil.Result, error) {
			switch {
			case strings.Contains(cmd, "get namespace"):
				return executil.Result{Stdout: "v1.2.3"}, nil
			case strings.Contains(cmd, "get deployment ax-workers"):
				return executil.Result{Stdout: "1"}, nil
			case unready != "" && strings.Contains(cmd, "wait --for=condition=Ready") && strings.Contains(cmd, unready):
				return executil.Result{}, fmt.Errorf("timed out waiting for the condition on %s", unready)
			}
			return executil.Result{}, nil
		}}
		k := &kubeHelper{runner: r, kubectl: "kubectl", context: "ax-local"}
		return k.alreadyHealthy(context.Background(), "v1.2.3", 1)
	}
	if !healthy("") {
		t.Fatal("alreadyHealthy = false with every pod Ready")
	}
	for _, unready := range []string{
		"pod/postgres-0",
		"app=podcertificate-controller",
		"app=ate-api-server",
		"app=ate-idp-server",
		"app=ate-controller",
		"app=atenet-router",
		"app=atenet-egress",
		"app=k8s-credential-provider",
		"app=atelet",
		"ate.dev/worker-pool=ax-workers",
	} {
		if healthy(unready) {
			t.Errorf("alreadyHealthy = true while %s is not Ready", unready)
		}
	}
}
