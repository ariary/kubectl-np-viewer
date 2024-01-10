package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubectl/pkg/cmd/util"
)

type Endpoint struct {
	Namespace *corev1.Namespace
	Pod       *corev1.Pod
}

// Runs the tester
func RunTester(configFlags *genericclioptions.ConfigFlags, cmd *cobra.Command) error {
	from, err := cmd.Flags().GetString("from")
	if err != nil {
		return errors.Wrap(err, "failed to get --from arg")
	}
	to, err := cmd.Flags().GetString("to")
	if err != nil {
		return errors.Wrap(err, "failed to get --to arg")
	}
	factory := util.NewFactory(configFlags)
	clientConfig := factory.ToRawKubeConfigLoader()
	config, err := factory.ToRESTConfig()

	if err != nil {
		return errors.Wrap(err, "failed to read kubeconfig")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "failed to create clientset")
	}
	namespace, _, err := clientConfig.Namespace()
	if err != nil {
		return errors.WithMessage(err, "Failed getting namespace")
	}

	// Parse endpoints
	fromEndpoint, err := parseEndpoint(clientset, from, namespace)
	if err != nil {
		return errors.Wrap(err, "Failed to parse 'from' endpoint")
	}
	toEndpoint, err := parseEndpoint(clientset, to, namespace)
	if err != nil {
		return errors.Wrap(err, "Failed to parse 'to' endpoint")
	}

	egressNp, ingressNp, err := NetpolTester(cmd, clientset, fromEndpoint, toEndpoint)
	if err != nil {
		return errors.Wrap(err, "An error occured during tester run")
	}

	if len(egressNp) > 0 && len(ingressNp) > 0 {
		fmt.Println("✅ Traffic authorized by netpol from", fromEndpoint.Pod.Name, "to", toEndpoint.Pod.Name)
	} else if len(egressNp) > 0 {
		fmt.Println("🟠 Only egress network policy authorized traffic from", fromEndpoint.Pod.Name, "to", toEndpoint.Pod.Name)
	} else if len(ingressNp) > 0 {
		fmt.Println("🟠 Only ingress network policy authorized traffic from", fromEndpoint.Pod.Name, "to", toEndpoint.Pod.Name)
	} else {
		fmt.Println("🔴 Traffic is not authorized by netpol from", fromEndpoint.Pod.Name, "to", toEndpoint.Pod.Name)
	}

	if len(egressNp) > 0 {
		fmt.Println("Egress authorized by netpol from", fromEndpoint.Pod.Name, "to", toEndpoint.Pod.Name)
	}
	return nil
}

// parseEndpoint: take an endpoint string and convert it in Endpoint struct
func parseEndpoint(clientset *kubernetes.Clientset, endpointStr string, namespace string) (e Endpoint, err error) {
	endpoint := strings.Split(endpointStr, ":")
	if len(endpoint) != 3 || len(endpoint) != 2 {
		return Endpoint{}, errors.Errorf("endpoint do not respect the right form (pod:[ns]:[pod_name] or pod:[pod_name])")
	}
	podname := endpoint[1]
	if len(endpoint) == 3 {
		namespace = endpoint[1]
		podname = endpoint[2]
	}
	e.Namespace, err = getNamespace(clientset, namespace)
	if err != nil {
		return Endpoint{}, errors.Errorf("failed to retrieve namespace spec for '%s'", endpoint[1])
	}
	if endpoint[0] == "pod" {
		e.Pod, err = getPod(clientset, e.Namespace.Name, podname)
		if err != nil {
			return Endpoint{}, errors.Errorf("failed to reretrieve pod %s(%s)", endpoint[2], e.Namespace.Name)
		}
	} else {
		return Endpoint{}, errors.Errorf("unsupported endpoint type '%s' (pod:[ns]:[pod_name] or pod:[pod_name])", endpoint[0])
	}

	return e, nil
}

// getNamespace: return a namespace given its name
func getNamespace(clientset *kubernetes.Clientset, namespace string) (result *corev1.Namespace, err error) {
	return clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
}

// NetpolTester: Core function that test if a traffic flux is possible from an endpoint to another
// TODO: handle new netpol, delete netpol, handle other endpoint that pod, handle port/tcp etc
func NetpolTester(cmd *cobra.Command, client *kubernetes.Clientset, from Endpoint, to Endpoint) (egressNp []v1.NetworkPolicy, ingressNp []v1.NetworkPolicy, err error) {
	//Todo deal with Endpoint.IsPod

	//is Egress auth OK
	//get netpol for the ns, no one OK, to namespace ok OR to pod is ok
	fromNetpol, err := getNetworkPolicies(client, from.Namespace.Name)
	if err != nil {
		return nil, nil, errors.Wrap(err, fmt.Sprintf("failed to retrieve netpol in namespace '%s'", from.Namespace))
	}
	//add netpol
	if fromNetpol, err = addNetworkPolicies(cmd, fromNetpol, from.Namespace.Name); err != nil {
		return nil, nil, errors.Wrap(err, "failed to add netpols")
	}
	// delete netpol
	if fromNetpol, err = deleteNetworkPolicies(cmd, fromNetpol); err != nil {
		return nil, nil, errors.Wrap(err, "failed to delete netpols")
	}
	var egressNetpolForm []v1.NetworkPolicy
	for _, netpol := range fromNetpol.Items {
		if containsEgressType(netpol.Spec.PolicyTypes) {
			egressNetpolForm = append(egressNetpolForm, netpol)
		}
		if len(netpol.Spec.Egress) != 0 {
			egressNetpolForm = append(egressNetpolForm, netpol)
		}
	}
	egressNp = isEgressOk(egressNetpolForm, from, to)
	//is Ingress auth OK
	ingressNp = isIngressOk(egressNetpolForm, from, to)
	return egressNp, ingressNp, nil
}

// Returns true if it contains IngressType
func containsIngressType(s []netv1.PolicyType) bool {
	return containsPolicyTypes(s, netv1.PolicyTypeIngress)
}

// Returns true if it contains IngressType
func containsEgressType(s []netv1.PolicyType) bool {
	return containsPolicyTypes(s, netv1.PolicyTypeEgress)
}

// isEgressOk: return true if an egress netpol allow traffic from and endpoint to another
func isEgressOk(netpol []v1.NetworkPolicy, from Endpoint, to Endpoint) []v1.NetworkPolicy {
	// if len(netpol) == 0 { //no Egress netpol

	// }
	// for _, egress := range netpol {
	// 	for _, egresses := range egress.Spec.Egress {
	// 		// If Wide
	// 		if egress.Spec.Egress == nil { // -to: []
	// 			continue
	// 		}
	// 		if egresses.To == nil {
	// 			//- to: {}
	// 		}
	// 		for _, peer := range egresses.To {

	// 			// if from.Namespace.Name != to.Namespace.Name {
	// 			// 	if !isSelectorMatch(to.Namespace.Labels, peer.NamespaceSelector) {
	// 			// 		return false
	// 			// 	}
	// 			// }
	// 		}
	// 	}
	// }
	return nil
}

func isIngressOk(netpol []v1.NetworkPolicy, from Endpoint, to Endpoint) []v1.NetworkPolicy {
	return nil
}
