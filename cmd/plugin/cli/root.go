package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/runoncloud/kubectl-np-viewer/pkg/logger"
	"github.com/runoncloud/kubectl-np-viewer/pkg/plugin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var (
	KubernetesConfigFlags *genericclioptions.ConfigFlags
)

func RootCmd() *cobra.Command {
	var ingress, egress, allNamespaces bool
	var pod, toPod, fromPod string
	var addNp, delNp []string

	cmd := &cobra.Command{
		Use:           "kubectl-np-viewer",
		Short:         "",
		Long:          `.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		PreRun: func(cmd *cobra.Command, args []string) {
			viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.NewLogger()
			log.Info("")

			finishedCh := make(chan bool, 1)
			go func() {
				for {
					select {
					case <-finishedCh:
						fmt.Printf("\r")
						return
					}
				}
			}()

			defer func() {
				finishedCh <- true
			}()

			if err := plugin.RunPlugin(KubernetesConfigFlags, cmd); err != nil {
				return errors.Cause(err)
			}
			return nil
		},
	}

	cobra.OnInitialize(initConfig)

	cmd.Flags().BoolVarP(&ingress, "ingress", "i", false,
		"Only selects network policies rules of type ingress")

	cmd.Flags().BoolVarP(&egress, "egress", "e", false,
		"Only selects network policies rules of type egress")

	cmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false,
		"Selects network policies rules from all namespaces")

	cmd.Flags().StringVarP(&pod, "pod", "p", "",
		"Only selects network policies rules applied to a specific pod")

	cmd.PersistentFlags().StringSliceVarP(&addNp, "add-np", "a", []string{},
		"Additional netpol to use without applying in the cluster.(must be relative path to netpol YAML file)")

	cmd.PersistentFlags().StringSliceVarP(&delNp, "del-np", "d", []string{},
		"Delete netpol from output. (must be netpol name)")

	cmd.Flags().StringVarP(&toPod, "to-pod", "t", "",
		"Only selects egress network policies rules enabling traffic to a specific pod. To specify a pod in the same ns --to-pod=[pod_name], in another namespace --to-pod=[ns]:[pod_name]")
	cmd.Flags().StringVarP(&fromPod, "from-pod", "f", "",
		"Only selects ingress network policies rules enabling traffic from a specific pod. To specify a pod in the same ns --from-pod=[pod_name], in another namespace --from-pod=[ns]:[pod_name]")
	cmd.MarkFlagsMutuallyExclusive("ingress", "to-pod")
	KubernetesConfigFlags = genericclioptions.NewConfigFlags(false)
	KubernetesConfigFlags.AddFlags(cmd.Flags())

	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	return cmd
}

func InitAndExecute() {
	if err := RootCmd().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	viper.AutomaticEnv()
}
