package plugins

import (
	"code.gitea.io/gitea/modules/setting"
	"os"
	"path/filepath"
	"plugin"
	"strings"
)

func LoadAll() error {
	pluginsPath := filepath.Join(setting.CustomPath, "plugins")
	return filepath.Walk(pluginsPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".so") {
			return nil
		}
		p, err := plugin.Open(path)
		if err != nil {
			return err
		}
		s, err := p.Lookup("StartPlugin")
		if err != nil {
			return err
		}
		if fnc, ok := s.(func()); ok {
			fnc()
		}
		return nil
	})
}
