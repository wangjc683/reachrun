//go:build linux && cgo && netcgo && !netgo

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		nativeAvailable: true,
		nativeByDefault: true,
		nativeBackend:   "linux-libc-nss",
		fallbackBackend: "go-dns-resolver",
	}
}
