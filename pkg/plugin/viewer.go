package plugin

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Runs the plugin
func RunPlugin(configFlags *genericclioptions.ConfigFlags, cmd *cobra.Command) error {
	// 	~ RunPlugin ns de from avec --to-pod
	// + ~ RunPlugin ns de to avec --from-pod

	tableLines, err := GetTableNetpolLines(configFlags, cmd)
	if err != nil {
		return err
	}

	if len(tableLines) == 0 {
		fmt.Println("No network policy was found")
	} else {
		renderTable(tableLines)
	}

	return nil
}

// Renders the result table
func renderTable(tableLines []TableLine) {
	var data [][]string
	for _, line := range tableLines {
		stringLine := []string{line.networkPolicyName, line.policyType, line.namespace, line.pods, line.policyNamespace,
			line.policyPods, line.policyIpBlock, line.policyPort}
		data = append(data, stringLine)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Network Policy", "Type", "Namespace", "Pods", "Namespaces Selector", "Pods Selector",
		"IP Block", "Ports"})
	table.SetAutoMergeCells(false)
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.AppendBulk(data)
	table.Render()
}
