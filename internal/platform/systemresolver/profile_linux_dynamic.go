//go:build linux && cgo && !netcgo && !netgo

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		nativeAvailable: true,
		nativeBackend:   "linux-libc-nss",
		fallbackBackend: "linux-resolver-selection-unverified",
		fallbackReason:  "backend_selection_unverified",
	}
}
