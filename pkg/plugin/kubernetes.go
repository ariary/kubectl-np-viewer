package plugin

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

// Returns the list of network policies
func getNetworkPolicies(clientset *kubernetes.Clientset, namespace string) (result *netv1.NetworkPolicyList,
	err error) {

	return clientset.NetworkingV1().NetworkPolicies(namespace).List(context.TODO(),
		metav1.ListOptions{})
}

// Returns the pod based on the name and namespace
func getPod(clientset *kubernetes.Clientset, namespace string, podName string) (result *corev1.Pod, err error) {
	selector := fields.OneTermEqualSelector("metadata.name", podName)
	podList, err := clientset.CoreV1().Pods(namespace).List(context.TODO(),
		metav1.ListOptions{FieldSelector: selector.String()})

	if len(podList.Items) == 0 {
		err = errors.New(fmt.Sprintf("Pods \"%s\" not found", podName))
	} else {
		result = &podList.Items[0]
	}
	return
}

// getNamespace: return a namespace given its name
func getNamespace(clientset *kubernetes.Clientset, namespace string) (result *corev1.Namespace, err error) {
	return clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
}
