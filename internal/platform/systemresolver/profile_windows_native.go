//go:build windows && !netgo

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		nativeAvailable: true,
		nativeByDefault: true,
		nativeBackend:   "windows-system-resolver",
		fallbackBackend: "go-dns-resolver",
	}
}
