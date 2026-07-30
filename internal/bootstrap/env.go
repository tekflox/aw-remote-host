package bootstrap

import "os"

// EnvPassthrough returns KEY=value entries for configured environment values
// that module install scripts are allowed to inherit from the launcher.
func EnvPassthrough(keys ...string) []string {
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}
