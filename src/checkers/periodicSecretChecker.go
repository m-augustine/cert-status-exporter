package checkers

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	// v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/m-augustine/cert-status-exporter/src/exporters"
	"github.com/m-augustine/cert-status-exporter/src/metrics"

	// acmev1 "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/acme/v1"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	certmanagerv1beta1 "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
)

// PeriodicSecretChecker is an object designed to check for files on disk at a regular interval
type PeriodicSecretChecker struct {
	period                  time.Duration
	labelSelectors          []string
	kubeconfigPath          string
	annotationSelectors     []string
	namespace               string
	exporter                *exporters.SecretExporter
	includeSecretsDataGlobs []string
	excludeSecretsDataGlobs []string
	includeSecretsTypes     []string
}

// NewSecretChecker is a factory method that returns a new PeriodicSecretChecker
func NewSecretChecker(period time.Duration, labelSelectors, includeSecretsDataGlobs, excludeSecretsDataGlobs, annotationSelectors []string, namespace, kubeconfigPath string, e *exporters.SecretExporter, includeSecretsTypes []string) *PeriodicSecretChecker {
	return &PeriodicSecretChecker{
		period:                  period,
		labelSelectors:          labelSelectors,
		annotationSelectors:     annotationSelectors,
		namespace:               namespace,
		kubeconfigPath:          kubeconfigPath,
		exporter:                e,
		includeSecretsDataGlobs: includeSecretsDataGlobs,
		excludeSecretsDataGlobs: excludeSecretsDataGlobs,
		includeSecretsTypes:     includeSecretsTypes,
	}
}

// StartChecking starts the periodic file check.  Most likely you want to run this as an independent go routine.
func (p *PeriodicSecretChecker) StartChecking() {
	config, err := clientcmd.BuildConfigFromFlags("", p.kubeconfigPath)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatalf("kubernetes.NewForConfig failed: %v", err)
	}

	certClient, err := certmanagerv1beta1.NewForConfig(config)
	if err != nil {
		glog.Fatalf("kubernetes.NewForConfig failed: %v", err)
	}

	periodChannel := time.Tick(p.period)

	for {
		glog.Info("Begin periodic check")

		p.exporter.ResetMetrics()

		var secrets []corev1.Secret
		var certs []certmanagerv1.Certificate

		var c *certmanagerv1.CertificateList
		c, err = certClient.Certificates(p.namespace).List(context.TODO(), metav1.ListOptions{})
		if err == nil {
			certs = c.Items
		} else {
			log.Print(err)

		}

		if len(p.labelSelectors) > 0 {
			for _, labelSelector := range p.labelSelectors {
				var s *corev1.SecretList
				s, err = client.CoreV1().Secrets(p.namespace).List(context.TODO(), metav1.ListOptions{
					LabelSelector: labelSelector,
				})
				if err != nil {
					break
				}

				secrets = append(secrets, s.Items...)
			}
		} else {
			var s *corev1.SecretList
			s, err = client.CoreV1().Secrets(p.namespace).List(context.TODO(), metav1.ListOptions{})
			if err == nil {
				secrets = s.Items
			}
		}

		if err != nil {
			glog.Errorf("Error requesting secrets %v", err)
			metrics.ErrorTotal.Inc()
			continue
		}

		for _, secret := range secrets {
			include, exclude := false, false
			// If you want only a certain type of cert
			if len(p.includeSecretsTypes) > 0 {
				exclude = false
				for _, t := range p.includeSecretsTypes {
					if string(secret.Type) == t {
						include = true
					}
					if include {
						continue
					}
				}
				if !include {
					glog.Infof("Ignoring secret %s in %s because %s is not included in your secret-include-types %v", secret.GetName(), secret.GetNamespace(), secret.Type, p.includeSecretsTypes)
					continue
				}
			}

			glog.Infof("Reviewing secret %v in %v", secret.GetName(), secret.GetNamespace())

			if len(p.annotationSelectors) > 0 {
				matches := false
				annotations := secret.GetAnnotations()
				for _, selector := range p.annotationSelectors {
					_, ok := annotations[selector]
					if ok {
						matches = true
						break
					}
				}

				if !matches {
					continue
				}
			}
			glog.Infof("Annotations matched. Parsing Secret.")

			for name, bytes := range secret.Data {
				include, exclude = false, false

				for _, glob := range p.includeSecretsDataGlobs {
					include, err = filepath.Match(glob, name)
					if err != nil {
						glog.Errorf("Error matching %v to %v: %v", glob, name, err)
						metrics.ErrorTotal.Inc()
						continue
					}

					if include {
						break
					}
				}

				for _, glob := range p.excludeSecretsDataGlobs {
					exclude, err = filepath.Match(glob, name)
					if err != nil {
						glog.Errorf("Error matching %v to %v: %v", glob, name, err)
						metrics.ErrorTotal.Inc()
						continue
					}

					if exclude {
						break
					}
				}

				if include && !exclude {
					// data, err := client.RESTClient().
					// 	Get().
					// 	AbsPath("/apis/certmanager.k8s.io/v1alpha1").
					// 	Namespace(secret.Namespace).
					// 	Resource("Certificates").
					// 	DoRaw(context.TODO())

					// var c vcert1.Certificate
					// err = json.Unmarshal(data, &c)
					// if err != nil {
					// 	panic(err)
					// }

					var condition v1.ConditionStatus

					for _, c := range certs {
						if c.Spec.SecretName == secret.Name {
							condition = c.Status.Conditions[0].Status
						}
					}

					glog.Infof("Publishing %v/%v metrics %v", secret.Name, secret.Namespace, name)
					err = p.exporter.ExportMetrics(bytes, name, secret.Name, secret.Namespace, string(condition))
					if err != nil {
						glog.Errorf("Error exporting secret %v", err)
						metrics.ErrorTotal.Inc()
					}
				} else {
					glog.Infof("Ignoring %v. Does not match %v or matches %v.", name, p.includeSecretsDataGlobs, p.excludeSecretsDataGlobs)
				}
			}
		}

		<-periodChannel
	}
}
