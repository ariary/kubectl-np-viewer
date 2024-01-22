package plugin

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Runs the plugin
func RuntTesterPlugin(configFlags *genericclioptions.ConfigFlags, cmd *cobra.Command) error {
	tableLines, err := GetTableNetpolLines(configFlags, cmd)
	if err != nil {
		return err
	}

	renderTable(tableLines)
	return nil
}
