package plugin

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubectl/pkg/cmd/util"
)

const (
	Deny     = "-"
	Wildcard = "*"
	Ingress  = "Ingress"
	Egress   = "Egress"
)

type SourceType int

type TableLine struct {
	networkPolicyName string
	namespace         string
	pods              string
	policyType        string
	policyNamespace   string
	policyPods        string
	policyIpBlock     string
	policyPort        string
}

const (
	PodSelector             SourceType = 1
	NamespaceSelector       SourceType = 2
	IpBlock                 SourceType = 3
	PodAndNameSpaceSelector SourceType = 4
)

// GetTableNetpolLines: get all the netpols corresponding to the research
func GetTableNetpolLines(configFlags *genericclioptions.ConfigFlags, cmd *cobra.Command) ([]TableLine, error) {
	factory := util.NewFactory(configFlags)
	clientConfig := factory.ToRawKubeConfigLoader()
	config, err := factory.ToRESTConfig()

	if err != nil {
		return nil, errors.Wrap(err, "failed to read kubeconfig")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create clientset")
	}

	namespace, _, err := clientConfig.Namespace()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed getting namespace")
	}

	isIngress := getFlagBool(cmd, "ingress")
	isEgress := getFlagBool(cmd, "egress")
	podName := util.GetFlagString(cmd, "pod")
	toPodName := util.GetFlagString(cmd, "to-pod")
	fromPodName := util.GetFlagString(cmd, "from-pod")

	if getFlagBool(cmd, "all-namespaces") {
		namespace = ""
	}

	networkPolicies, err := getNetworkPolicies(clientset, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list network policies")
	}
	//add netpol
	if networkPolicies, err = addNetworkPolicies(cmd, networkPolicies, namespace); err != nil {
		return nil, errors.Wrap(err, "failed to add netpols")
	}
	// delete netpol
	if networkPolicies, err = deleteNetworkPolicies(cmd, networkPolicies); err != nil {
		return nil, errors.Wrap(err, "failed to delete netpols")
	}

	var tableLines []TableLine
	for _, policy := range networkPolicies.Items {

		if isIngress || (!isIngress && !isEgress) {
			// If Default Deny
			if containsPolicyTypes(policy.Spec.PolicyTypes, netv1.PolicyTypeIngress) && policy.Spec.Ingress == nil {
				tableLines = append(tableLines, createTableLineWithDeny(policy, Ingress))
			}

			for _, ingresses := range policy.Spec.Ingress {
				// If Wide Open
				if ingresses.From == nil && ingresses.Ports == nil {
					tableLines = append(tableLines, createTableLineWithWildcard(policy, Ingress))
					continue
				}
				for _, peer := range ingresses.From {
					if peer.PodSelector != nil && peer.NamespaceSelector != nil {
						tableLines = append(tableLines, createTableLineForSourceType(policy, peer, ingresses.Ports,
							Ingress, PodAndNameSpaceSelector))
					} else {
						if peer.PodSelector != nil {
							tableLines = append(tableLines, createTableLineForSourceType(policy, peer, ingresses.Ports,
								Ingress, PodSelector))
						}
						if peer.NamespaceSelector != nil {
							tableLines = append(tableLines, createTableLineForSourceType(policy, peer, ingresses.Ports,
								Ingress, NamespaceSelector))
						}
					}
					if peer.IPBlock != nil {
						tableLines = append(tableLines, createTableLineForSourceType(policy, peer, ingresses.Ports,
							Ingress, IpBlock))
					}
				}
				if len(ingresses.Ports) > 0 && len(ingresses.From) == 0 {
					tableLines = append(tableLines, createTableLineForPortBlock(policy, ingresses.Ports, Ingress))
				}
			}
		}

		if isEgress || (!isEgress && !isIngress) {
			// If Default Deny
			if containsPolicyTypes(policy.Spec.PolicyTypes, netv1.PolicyTypeEgress) && policy.Spec.Egress == nil {
				tableLines = append(tableLines, createTableLineWithDeny(policy, Egress))
			}

			for _, egresses := range policy.Spec.Egress {
				// If Wide Open
				if egresses.To == nil && egresses.Ports == nil {
					tableLines = append(tableLines, createTableLineWithWildcard(policy, Egress))
					continue
				}

				for _, peer := range egresses.To {
					if peer.PodSelector != nil && peer.NamespaceSelector != nil {
						tableLines = append(tableLines, createTableLineForSourceType(policy, peer, egresses.Ports,
							Egress, PodAndNameSpaceSelector))
					} else {
						if peer.PodSelector != nil {
							tableLines = append(tableLines, createTableLineForSourceType(policy, peer, egresses.Ports,
								Egress, PodSelector))
						}
						if peer.NamespaceSelector != nil {
							tableLines = append(tableLines, createTableLineForSourceType(policy, peer, egresses.Ports,
								Egress, NamespaceSelector))
						}
					}
					if peer.IPBlock != nil {
						tableLines = append(tableLines, createTableLineForSourceType(policy, peer, egresses.Ports,
							Egress, IpBlock))
					}
				}
				if len(egresses.Ports) > 0 && len(egresses.To) == 0 {
					tableLines = append(tableLines, createTableLineForPortBlock(policy, egresses.Ports, Egress))
				}
			}
		}
	}

	if len(podName) > 0 {
		pod, err := getPod(clientset, namespace, podName)
		if err != nil {
			return nil, errors.Wrap(err, "failed getting pod")
		}
		tableLines = filterLinesBasedOnPodLabels(tableLines, pod)
	}

	if toPodName != "" {
		toPod, toNamespace, err := parsePodEndpoint(clientset, toPodName, namespace)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize pod endpoint (--to)")
		}
		tableLines = filterLinesBasedOnToPodLabels(tableLines, toPod, toNamespace)
	}

	if fromPodName != "" {
		fromPod, fromNamespace, err := parsePodEndpoint(clientset, fromPodName, namespace)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize pod endpoint (--from)")
		}

		tableLines = filterLinesBasedOnFromPodLabels(tableLines, fromPod, fromNamespace)
	}

	return tableLines, nil
}

// Creates a new line for the result table
func createTableLine(policy netv1.NetworkPolicy, ports []netv1.NetworkPolicyPort,
	policyType string) TableLine {

	var line TableLine
	line.networkPolicyName = policy.Name
	line.namespace = policy.Namespace
	line.policyType = policyType

	if policy.Spec.PodSelector.Size() == 0 {
		line.pods = Wildcard
	} else {
		line.pods = sortAndJoinLabels(policy.Spec.PodSelector)
	}

	if len(ports) == 0 {
		line.policyPort = Wildcard
	} else {
		for _, port := range ports {
			line.policyPort = addCharIfNotEmpty(line.policyPort, "\n") +
				fmt.Sprintf("%s:%s", getProtocol(*port.Protocol), port.Port)
		}
	}
	return line
}

func createTableLineWithDeny(policy netv1.NetworkPolicy, policyType string) TableLine {
	line := createTableLine(policy, []netv1.NetworkPolicyPort{}, policyType)
	line.policyPods = Deny
	line.policyIpBlock = Deny
	line.policyNamespace = Deny
	line.policyPort = Deny
	return line
}

func createTableLineWithWildcard(policy netv1.NetworkPolicy, policyType string) TableLine {
	line := createTableLine(policy, []netv1.NetworkPolicyPort{}, policyType)
	line.policyPods = Wildcard
	line.policyIpBlock = Wildcard
	line.policyNamespace = Wildcard
	return line
}

// Creates a new line for the result table for a specific source type
func createTableLineForSourceType(policy netv1.NetworkPolicy, peer netv1.NetworkPolicyPeer, ports []netv1.NetworkPolicyPort,
	policyType string, sourceType SourceType) TableLine {

	line := createTableLine(policy, ports, policyType)

	if sourceType == PodSelector {
		line.policyPods = sortAndJoinLabels(*peer.PodSelector)
		line.policyNamespace = line.namespace
		line.policyIpBlock = Wildcard
	}

	if sourceType == NamespaceSelector {
		line.policyNamespace = sortAndJoinLabels(*peer.NamespaceSelector)
		line.policyPods = Wildcard
		line.policyIpBlock = Wildcard
	}

	if sourceType == PodAndNameSpaceSelector {
		line.policyNamespace = sortAndJoinLabels(*peer.NamespaceSelector)
		line.policyPods = sortAndJoinLabels(*peer.PodSelector)
		line.policyIpBlock = Wildcard
	}

	if sourceType == IpBlock {
		var exceptions string
		for _, exception := range peer.IPBlock.Except {
			exceptions = addCharIfNotEmpty(exceptions, "\n") + exception
		}
		line.policyIpBlock = fmt.Sprintf("CIDR: %s Except: [%s]", peer.IPBlock.CIDR, exceptions)
		line.policyPods = Wildcard
		line.policyNamespace = Wildcard
	}

	return line
}

// Creates a new line for the result table for a rule that only have ports
func createTableLineForPortBlock(policy netv1.NetworkPolicy, ports []netv1.NetworkPolicyPort,
	policyType string) TableLine {

	line := createTableLine(policy, ports, policyType)
	line.policyNamespace = Wildcard
	line.policyPods = Wildcard
	line.policyIpBlock = Wildcard
	return line
}

// Sorts and joins the labels with a new space delimiter based on podSelector field
func sortAndJoinLabels(podSelector metav1.LabelSelector) string {
	var macthExpressionLines string
	if len(podSelector.MatchExpressions) != 0 {
		macthExpressionLines = sortAndJoinLabelsForMatchExpressions(podSelector.MatchExpressions)
	}

	return macthExpressionLines + sortAndJoinLabelsForMatchLabels(podSelector.MatchLabels)
}

// Sorts and joins the labels with a new space delimiter by parsing MatchLabels field
func sortAndJoinLabelsForMatchLabels(labels map[string]string) string {
	result := ""
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		result = addCharIfNotEmpty(result, "\n") + fmt.Sprintf("%s=%s", k, labels[k])
	}

	return result
}

// Sorts and joins the labels with a new space delimiter by parsing MatchExpressions field
// possible operators: Exists, DoesNotExist, In, NotIn
func sortAndJoinLabelsForMatchExpressions(matchExpressions []metav1.LabelSelectorRequirement) string {
	result := ""
	for _, expression := range matchExpressions {
		key := expression.Key
		switch expression.Operator {
		case metav1.LabelSelectorOpExists:
			result = addCharIfNotEmpty(result, "\n") + fmt.Sprintf("%s=%s", key, "*")
		case metav1.LabelSelectorOpDoesNotExist:
			result = addCharIfNotEmpty(result, "\n") + fmt.Sprintf("!(%s)=%s", key, "*")
		case metav1.LabelSelectorOpIn:
			labelValues := "(" + strings.Join(expression.Values, "|") + ")"
			result = addCharIfNotEmpty(result, "\n") + fmt.Sprintf("%s=%s", key, labelValues)
		case metav1.LabelSelectorOpNotIn:
			labelValues := "(" + strings.Join(expression.Values, "|") + ")"
			result = addCharIfNotEmpty(result, "\n") + fmt.Sprintf("%s=%s", key, "!"+labelValues)
		}
	}

	return result
}

// Returns the protocol as string
func getProtocol(protocol corev1.Protocol) string {
	switch protocol {
	case corev1.ProtocolSCTP:
		return "SCTP"
	case corev1.ProtocolUDP:
		return "UDP"
	case corev1.ProtocolTCP:
		return "TCP"
	default:
		return ""
	}
}

// Adds the char c to the string s if the string s is not empty
func addCharIfNotEmpty(s string, c string) string {
	if len(s) > 0 {
		return s + c
	}
	return s
}

// Gets the the flag value as a boolean, otherwise returns false if the flag value is nil
func getFlagBool(cmd *cobra.Command, flag string) bool {
	b, err := cmd.Flags().GetBool(flag)
	if err != nil {
		return false
	}
	return b
}

// Filters lines in the result table based on the pod labels
func filterLinesBasedOnPodLabels(tableLines []TableLine, pod *corev1.Pod) []TableLine {
	var filteredTable []TableLine
	for _, line := range tableLines {
		if line.pods != Wildcard {
			labels := strings.Split(line.pods, "\n")
			appendLine := true
			for _, labelCondition := range labels {
				if !checkLabelCondition(labelCondition, pod.Labels) {
					appendLine = false
					break
				}
			}
			if appendLine {
				filteredTable = append(filteredTable, line)
			}
		} else {
			filteredTable = append(filteredTable, line)
		}
	}
	return filteredTable
}

// Filters lines in the result table based on the pod and s labels. Depending on the pod/ns labels we will filter either on egress traffic or on ingress traffic.
// policyTypeFilter: Ingress if we want to only look at egress traffic, Egress otherwise
func filterLinesBasedOnSpecifictraffic(tableLines []TableLine, pod *corev1.Pod, ns *corev1.Namespace, policyTypeFilter string) []TableLine {
	var filteredTable []TableLine
	for _, line := range tableLines {
		if line.policyType != policyTypeFilter {
			continue
		}

		// Either only Pod Selector, or NamespaceSelector Or both
		if !checkPolicyConditionWithLabels(line.policyPods, pod.Labels) {
			continue
		}

		if !checkPolicyConditionWithLabels(line.policyNamespace, ns.Labels) {
			continue
		}

		// if here pod & ns selector ok
		filteredTable = append(filteredTable, line)

	}

	return filteredTable
}

// Filters lines in the result table based on the pod labels that we want to target with egress traffic
func filterLinesBasedOnToPodLabels(tableLines []TableLine, pod *corev1.Pod, ns *corev1.Namespace) []TableLine {
	return filterLinesBasedOnSpecifictraffic(tableLines, pod, ns, Egress)
}

// Filters lines in the result table based on the pod labels that we accept ingress from
func filterLinesBasedOnFromPodLabels(tableLines []TableLine, pod *corev1.Pod, ns *corev1.Namespace) []TableLine {
	return filterLinesBasedOnSpecifictraffic(tableLines, pod, ns, Ingress)
}

// checkPolicyCondition: check that a policy (string) is affecting labels
func checkPolicyConditionWithLabels(condition string, labels map[string]string) (ok bool) {
	if condition == Wildcard {
		return true
	}

	if condition == Deny {
		return false
	}

	conditionLabels := strings.Split(condition, "\n")
	for _, conditionLabel := range conditionLabels {
		if !checkLabelCondition(conditionLabel, labels) {
			return false
		}
	}

	return true
}

// checkLabelCondition: check that a single label selector condition line is satisfied given a pod/ns labels.
// It support matchLabels and matchExpressions conditions type
func checkLabelCondition(labelCondition string, labels map[string]string) bool {
	keyValue := strings.Split(labelCondition, "=")
	key := keyValue[0]
	value := keyValue[1]
	if strings.HasPrefix(key, "!(") { // Label line: '!(label)=*'
		return checkDoesNotExistCondition(key, labels)
	} else if value == "*" { // prefix should be != '!(' also, Label line: 'label=*'
		return checkExistCondition(key, labels)
	} else if strings.HasPrefix(value, "!(") { // Label line: 'label=(value1|...|valueN)'
		return checkNotInCondition(key, value, labels)
	} else if strings.HasPrefix(value, "(") { // Label line: 'label=!(value1|...|valueN)'
		return checkInCondition(key, value, labels)
	} else if labels[keyValue[0]] != keyValue[1] { // simple label filter
		return false
	}

	return true
}

// checkExistCondition: check an Exist filter against a pod spec. label line: 'label=*'.
// Return true if the label key exist in pod spec
func checkExistCondition(key string, labels map[string]string) bool {
	key = strings.TrimSuffix(strings.TrimPrefix(key, "("), ")")
	_, exist := labels[key]
	return exist
}

// checkDoesNotExistCondition: check a DoesNotExist filter against a pod spec. Label line: '!(label)=*'
// // Return true if the label key does not exist in pod spec
func checkDoesNotExistCondition(key string, labels map[string]string) bool {
	isolateKey := strings.TrimSuffix(strings.TrimPrefix(key, "!("), ")")
	return !checkExistCondition(isolateKey, labels)
}

// checkInCondition: check an NotIn filter against a pod spec. label line: 'label=(value1|...|valueN)'
// Return true if the label key if and only if the label exist and does not have specific values
func checkInCondition(key, value string, labels map[string]string) bool {
	podLabelValue, exist := labels[key]
	if !exist {
		return false
	}

	values := strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, "("), ")"), "|")
	for _, value := range values {
		if value == podLabelValue {
			return true
		}
	}
	return false
}

// checkNotInCondition: check an NotIn filter against a pod spec. label line: 'label=!(value1|...|valueN)'
// Return true if the label key is not set in pod OR do not have specific values
func checkNotInCondition(key, value string, labels map[string]string) bool {
	return !checkInCondition(key, strings.TrimPrefix(value, "!"), labels)
}

// Returns true if the slice contains the policy type
func containsPolicyTypes(s []netv1.PolicyType, value netv1.PolicyType) bool {
	for _, a := range s {
		if a == value {
			return true
		}
	}
	return false
}

// decodeNetpolFromYaml: decode a NetworkPolicy YAML declaration within struct
func decodeNetpolFromYaml(file string) (netpol *netv1.NetworkPolicy, err error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	stream, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read netpol YAML file")
	}
	obj, gKV, err := decode(stream, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode netpol YAML file")
	}
	if gKV.Kind == "NetworkPolicy" {
		netpol = obj.(*netv1.NetworkPolicy)
	}
	return netpol, nil
}

// deleteNetworkPolicies:delete specified netpols
func deleteNetworkPolicies(cmd *cobra.Command, networkPolicies *netv1.NetworkPolicyList) (*netv1.NetworkPolicyList, error) {
	delNp, err := cmd.Flags().GetStringSlice("del-np")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get list from --del-np flag")
	}
	for _, netpol := range delNp {
		networkPolicies.Items = deleteNetworkPolicy(networkPolicies.Items, netpol)
	}
	return networkPolicies, nil
}

// deleteNetworkPolicy: delete a network policy from a list
func deleteNetworkPolicy(networkPolicies []netv1.NetworkPolicy, nameToDelete string) []netv1.NetworkPolicy {
	var updatedList []netv1.NetworkPolicy

	for _, policy := range networkPolicies {
		if policy.Name != nameToDelete {
			updatedList = append(updatedList, policy)
		}
	}

	return updatedList
}

// addNetworkPolicies: add all netpols
func addNetworkPolicies(cmd *cobra.Command, networkPolicies *netv1.NetworkPolicyList, namespace string) (*netv1.NetworkPolicyList, error) {
	addNp, err := cmd.Flags().GetStringSlice("add-np")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get list from --add-np flag")
	}
	for _, yamlNp := range addNp {
		if networkPolicies.Items, err = addNetworkPolicy(networkPolicies.Items, yamlNp, namespace); err != nil {
			return nil, errors.Wrap(err, "failed to get add netpol")
		}
	}
	return networkPolicies, nil
}

// addNetworkPolicy: add a network policy within a list
func addNetworkPolicy(networkPolicies []netv1.NetworkPolicy, file string, namespace string) ([]netv1.NetworkPolicy, error) {
	netpol, err := decodeNetpolFromYaml(file)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode yaml file")
	}
	if netpol.Namespace == namespace || namespace == "" {
		networkPolicies = append(networkPolicies, *netpol)
	}

	return networkPolicies, nil
}

// parsePodEndpoint: parse pod endpoint [ns]:[pod_name] or juste [pod] and return ns and pod struct associated
func parsePodEndpoint(clientset *kubernetes.Clientset, podName string, namespace string) (pod *corev1.Pod, ns *corev1.Namespace, err error) {
	podEndpoint := strings.Split(podName, ":")
	if len(podEndpoint) == 2 {
		namespace = podEndpoint[0]
		podName = podEndpoint[1]
	}
	pod, err = getPod(clientset, namespace, podName)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed getting pod")
	}
	// check ns selector
	ns, err = getNamespace(clientset, namespace)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed retrieveing ns")
	}
	return pod, ns, nil
}
