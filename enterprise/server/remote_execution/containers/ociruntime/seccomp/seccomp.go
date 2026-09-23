//go:build linux

package seccomp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strconv"
	"syscall"

	_ "embed"

	mobyseccomp "github.com/moby/profiles/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

//go:embed seccomp.json
var defaultProfileJSON []byte

// The embedded profile was copied from Podman. In addition to Docker's archMap
// and conditional syscall rules, it has symbolic errno fields. Moby handles the
// Docker fields, but only reads the numeric errno fields. Keep the Podman fields
// visible while decoding so that we can verify their numeric equivalents before
// converting the profile.
type podmanProfile struct {
	mobyseccomp.Seccomp
	DefaultErrno string           `json:"defaultErrno,omitempty"`
	Syscalls     []*podmanSyscall `json:"syscalls"`
}

type podmanSyscall struct {
	mobyseccomp.Syscall
	Errno string `json:"errno,omitempty"`
}

// New constructs an OCI seccomp profile from the embedded Podman default for
// the native architecture and the container's bounding capabilities. It appends
// an allow rule for any additional syscalls configured by the executor operator.
// The configured names are removed from the default rules so that the appended
// allow rule is the only rule matching them.
func New(additionalSyscalls, boundingCapabilities []string) (*specs.LinuxSeccomp, error) {
	profile, err := loadProfile(defaultProfileJSON, boundingCapabilities)
	if err != nil {
		return nil, err
	}
	if len(additionalSyscalls) == 0 {
		return profile, nil
	}

	names := slices.Clone(additionalSyscalls)
	slices.Sort(names)
	names = slices.Compact(names)

	// Remove the configured names from the default rules. Runtimes resolve
	// conflicting rules for the same syscall in unspecified ways, so leaving a
	// default rule in place would make the outcome unpredictable. In
	// particular, crun keeps whichever rule for a syscall comes first, which
	// would make a default deny rule silently win over the appended allow
	// rule.
	for i := range profile.Syscalls {
		rule := &profile.Syscalls[i]
		rule.Names = slices.DeleteFunc(rule.Names, func(name string) bool {
			return slices.Contains(names, name)
		})
	}
	profile.Syscalls = slices.DeleteFunc(profile.Syscalls, func(rule specs.LinuxSyscall) bool {
		return len(rule.Names) == 0
	})

	profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
		Names:  names,
		Action: specs.ActAllow,
	})
	return profile, nil
}

func loadProfile(profileJSON []byte, boundingCapabilities []string) (*specs.LinuxSeccomp, error) {
	var source podmanProfile
	decoder := json.NewDecoder(bytes.NewReader(profileJSON))
	// Dropping an unrecognized condition can turn a conditional allow rule
	// into an unconditional one. Fail closed if the source format changes.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("parse seccomp profile: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse seccomp profile: expected one JSON object")
	}
	if err := validateErrno(source.DefaultErrno, source.DefaultErrnoRet); err != nil {
		return nil, fmt.Errorf("default seccomp errno: %w", err)
	}
	for i, rule := range source.Syscalls {
		if rule == nil {
			return nil, fmt.Errorf("seccomp syscall rule %d is null", i)
		}
		if err := validateErrno(rule.Errno, rule.ErrnoRet); err != nil {
			return nil, fmt.Errorf("seccomp syscall rule %d errno: %w", i, err)
		}
		source.Seccomp.Syscalls = append(source.Seccomp.Syscalls, &rule.Syscall)
	}
	normalizedJSON, err := json.Marshal(&source.Seccomp)
	if err != nil {
		return nil, fmt.Errorf("normalize seccomp profile: %w", err)
	}
	profile, err := mobyseccomp.LoadProfile(string(normalizedJSON), &specs.Spec{
		Process: &specs.Process{
			Capabilities: &specs.LinuxCapabilities{Bounding: boundingCapabilities},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("convert seccomp profile to OCI: %w", err)
	}
	if profile == nil {
		return nil, fmt.Errorf("seccomp profile must not disable seccomp")
	}
	if len(source.ArchMap) > 0 && len(profile.Architectures) == 0 {
		return nil, fmt.Errorf("seccomp archMap has no entry for native architecture %q", runtime.GOARCH)
	}
	return profile, nil
}

func validateErrno(name string, value *uint) error {
	if name == "" {
		return nil
	}
	if value == nil {
		return fmt.Errorf("errno %q requires a numeric errnoRet", name)
	}
	if n, err := strconv.ParseUint(name, 10, 64); err == nil && n == uint64(*value) {
		return nil
	}
	if unix.ErrnoName(syscall.Errno(*value)) == name {
		return nil
	}
	return fmt.Errorf("errno %q does not match errnoRet %d", name, *value)
}
