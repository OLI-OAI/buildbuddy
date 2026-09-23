//go:build linux

package seccomp

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestNew_DefaultArchitectures(t *testing.T) {
	var want []specs.Arch
	switch runtime.GOARCH {
	case "amd64":
		want = []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	case "arm64":
		want = []specs.Arch{specs.ArchAARCH64, specs.ArchARM}
	default:
		t.Skip("OCI runtime binaries are only provided for amd64 and arm64")
	}

	profile, err := New(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, want, profile.Architectures)
	assert.Equal(t, specs.ActErrno, profile.DefaultAction)
	require.NotNil(t, profile.DefaultErrnoRet)
	assert.Equal(t, uint(38), *profile.DefaultErrnoRet)

	var archPrctlRules []specs.LinuxSyscall
	for _, rule := range profile.Syscalls {
		if slices.Contains(rule.Names, "arch_prctl") {
			archPrctlRules = append(archPrctlRules, rule)
		}
	}
	if runtime.GOARCH == "amd64" {
		require.Len(t, archPrctlRules, 1)
		assert.Equal(t, specs.ActAllow, archPrctlRules[0].Action)
	} else {
		assert.Empty(t, archPrctlRules)
	}
}

func TestNew_CapabilityConditionalRules(t *testing.T) {
	for _, tc := range []struct {
		name         string
		capabilities []string
		wantAction   specs.LinuxSeccompAction
	}{
		{name: "without ptrace", wantAction: specs.ActErrno},
		{name: "with ptrace", capabilities: []string{"CAP_SYS_PTRACE"}, wantAction: specs.ActAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := New(nil, tc.capabilities)
			require.NoError(t, err)
			var matchingRules []specs.LinuxSyscall
			for _, rule := range profile.Syscalls {
				if slices.Contains(rule.Names, "kcmp") {
					matchingRules = append(matchingRules, rule)
				}
			}
			require.Len(t, matchingRules, 1)
			assert.Equal(t, tc.wantAction, matchingRules[0].Action)
		})
	}
}

func TestNew_SocketPolicy(t *testing.T) {
	for _, tc := range []struct {
		name               string
		capabilities       []string
		wantAllowRules     int
		wantAuditDenyRules int
	}{
		{name: "without audit write", wantAllowRules: 3, wantAuditDenyRules: 1},
		{name: "with audit write", capabilities: []string{"CAP_AUDIT_WRITE"}, wantAllowRules: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := New(nil, tc.capabilities)
			require.NoError(t, err)
			allowRules, algDenyRules, auditDenyRules := 0, 0, 0
			for _, rule := range profile.Syscalls {
				if !slices.Contains(rule.Names, "socket") {
					continue
				}
				if rule.Action == specs.ActAllow {
					allowRules++
					assert.Contains(t, rule.Args, specs.LinuxSeccompArg{Index: 0, Value: 38, Op: specs.OpNotEqual})
				}
				if rule.Action == specs.ActErrno && slices.Contains(rule.Args, specs.LinuxSeccompArg{Index: 0, Value: 38, Op: specs.OpEqualTo}) {
					algDenyRules++
					require.NotNil(t, rule.ErrnoRet)
					assert.Equal(t, uint(1), *rule.ErrnoRet)
				}
				if rule.Action == specs.ActErrno && slices.Contains(rule.Args, specs.LinuxSeccompArg{Index: 0, Value: 16, Op: specs.OpEqualTo}) {
					auditDenyRules++
				}
			}
			assert.Equal(t, tc.wantAllowRules, allowRules)
			assert.Equal(t, 1, algDenyRules)
			assert.Equal(t, tc.wantAuditDenyRules, auditDenyRules)
		})
	}
}

func TestLoadProfile_RejectsUnsupportedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		profile   string
		wantError string
	}{
		{name: "unknown condition", profile: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["kcmp"],"action":"SCMP_ACT_ALLOW","includes":{"unknownCondition":true}}]}`, wantError: "unknown field"},
		{name: "missing numeric default errno", profile: `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrno":"ENOSYS","syscalls":[]}`, wantError: "requires a numeric errnoRet"},
		{name: "mismatched default errno", profile: `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrno":"ENOSYS","defaultErrnoRet":1,"syscalls":[]}`, wantError: "does not match"},
		{name: "mismatched syscall errno", profile: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["kcmp"],"action":"SCMP_ACT_ERRNO","errno":"EPERM","errnoRet":38}]}`, wantError: "does not match"},
		{name: "null rule", profile: `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[null]}`, wantError: "rule 0 is null"},
		{name: "disabled profile", profile: `{}`, wantError: "must not disable seccomp"},
		{name: "unmatched architecture", profile: `{"defaultAction":"SCMP_ACT_ERRNO","archMap":[{"architecture":"SCMP_ARCH_UNKNOWN"}],"syscalls":[]}`, wantError: "no entry for native architecture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadProfile([]byte(tc.profile), nil)
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

func TestNew_AdditionalSyscalls(t *testing.T) {
	additionalSyscalls := []string{
		"io_uring_setup",
		"io_uring_enter",
		"io_uring_register",
		"io_uring_setup",
	}
	profile, err := New(additionalSyscalls, nil)
	require.NoError(t, err)

	wantNames := []string{
		"io_uring_enter",
		"io_uring_register",
		"io_uring_setup",
	}
	matchingRules := 0
	for _, rule := range profile.Syscalls {
		for _, name := range rule.Names {
			if !strings.HasPrefix(name, "io_uring_") {
				continue
			}
			matchingRules++
			assert.Equal(t, specs.ActAllow, rule.Action)
			assert.Empty(t, rule.Args)
			assert.Equal(t, wantNames, rule.Names)
			break
		}
	}
	assert.Equal(t, 1, matchingRules)
	assert.Equal(t, []string{
		"io_uring_setup",
		"io_uring_enter",
		"io_uring_register",
		"io_uring_setup",
	}, additionalSyscalls)
}

func TestNew_AdditionalSyscallsOverrideDefaultDenyRules(t *testing.T) {
	// The default profile has deny rules covering userfaultfd and setns.
	// userfaultfd's only matching rule is a deny. Without CAP_SYS_ADMIN,
	// setns appears in the default allow list and a conditional deny rule.
	defaultProfile, err := New(nil, nil)
	require.NoError(t, err)
	for _, name := range []string{"userfaultfd", "setns"} {
		denyRules := 0
		for _, rule := range defaultProfile.Syscalls {
			if slices.Contains(rule.Names, name) && rule.Action == specs.ActErrno {
				denyRules++
			}
		}
		require.GreaterOrEqual(t, denyRules, 1, "expected a default deny rule for %q", name)
	}

	// Allow both syscalls. Expect the appended allow rule to become the only
	// rule matching them. Keeping the default rules in place would leave the
	// outcome to runtime-specific conflict resolution. crun keeps whichever
	// rule for a syscall comes first, so userfaultfd would stay denied.
	// setns exercises removing a name that appears in several rules,
	// including allow rules that precede its deny rule.
	profile, err := New([]string{"userfaultfd", "setns"}, nil)
	require.NoError(t, err)
	for _, name := range []string{"userfaultfd", "setns"} {
		var matchingRules []specs.LinuxSyscall
		for _, rule := range profile.Syscalls {
			if slices.Contains(rule.Names, name) {
				matchingRules = append(matchingRules, rule)
			}
		}
		require.Len(t, matchingRules, 1, "expected exactly one rule for %q", name)
		assert.Equal(t, specs.ActAllow, matchingRules[0].Action)
		assert.Empty(t, matchingRules[0].Args)
	}

	// Expect syscalls that share a default rule with the configured names to
	// remain denied. The default rule denying userfaultfd also denies
	// vmsplice.
	var vmspliceActions []specs.LinuxSeccompAction
	for _, rule := range profile.Syscalls {
		if slices.Contains(rule.Names, "vmsplice") {
			vmspliceActions = append(vmspliceActions, rule.Action)
		}
	}
	assert.Equal(t, []specs.LinuxSeccompAction{specs.ActErrno}, vmspliceActions)
}
