package plugins

import "fmt"

// Registry holds the compiled-in plugins. The CLI populates it at init().
type Registry struct {
	auths      map[string]Authenticator
	installers map[string]Installer
}

func NewRegistry() *Registry {
	return &Registry{
		auths:      map[string]Authenticator{},
		installers: map[string]Installer{},
	}
}

func (r *Registry) RegisterAuthenticator(a Authenticator) {
	r.auths[a.Name()] = a
}

func (r *Registry) RegisterInstaller(i Installer) {
	r.installers[i.Name()] = i
}

func (r *Registry) Authenticator(name string) (Authenticator, error) {
	a, ok := r.auths[name]
	if !ok {
		return nil, fmt.Errorf("plugins: authenticator %q not found (built-in: %v)", name, r.authNames())
	}
	return a, nil
}

func (r *Registry) Installer(name string) (Installer, error) {
	i, ok := r.installers[name]
	if !ok {
		return nil, fmt.Errorf("plugins: installer %q not found (built-in: %v)", name, r.installerNames())
	}
	return i, nil
}

func (r *Registry) authNames() []string {
	out := make([]string, 0, len(r.auths))
	for k := range r.auths {
		out = append(out, k)
	}
	return out
}

func (r *Registry) installerNames() []string {
	out := make([]string, 0, len(r.installers))
	for k := range r.installers {
		out = append(out, k)
	}
	return out
}

// Authenticators returns all registered authenticators, in unspecified order.
func (r *Registry) Authenticators() []Authenticator {
	out := make([]Authenticator, 0, len(r.auths))
	for _, a := range r.auths {
		out = append(out, a)
	}
	return out
}

// Installers returns all registered installers, in unspecified order.
func (r *Registry) Installers() []Installer {
	out := make([]Installer, 0, len(r.installers))
	for _, i := range r.installers {
		out = append(out, i)
	}
	return out
}
