package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nrdcg/desec"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	challengeLabel = "_acme-challenge"
	recordTTL      = 3600
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		klog.Fatal("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName, &desecDNSProviderSolver{})
}

type desecDNSProviderSolver struct {
	client kubernetes.Interface
	// baseURL overrides the deSEC API endpoint; tests point it at a fake.
	baseURL string
}

type desecDNSProviderConfig struct {
	APIKeySecretRef v1.SecretKeySelector `json:"apiKeySecretRef"`
}

func (c *desecDNSProviderSolver) Name() string {
	return "desec"
}

func (c *desecDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl
	return nil
}

// Present adds the challenge key to the TXT RRset, keeping any keys already
// there: a leftover record or a concurrent challenge for the same name must not
// fail issuance.
func (c *desecDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()
	api, domain, subName, err := c.target(ctx, ch)
	if err != nil {
		return err
	}
	value := quote(ch.Key)

	existing, err := api.Records.Get(ctx, domain, subName, "TXT")
	switch {
	case isNotFound(err):
		_, err = api.Records.Create(ctx, desec.RRSet{
			Domain: domain, SubName: subName, Type: "TXT", TTL: recordTTL, Records: []string{value},
		})
	case err != nil:
		return fmt.Errorf("desec: read %s: %w", ch.ResolvedFQDN, err)
	case slices.Contains(existing.Records, value):
		return nil
	default:
		_, err = api.Records.Update(ctx, domain, subName, "TXT", desec.RRSet{
			Records: append(slices.Clone(existing.Records), value),
		})
	}
	if err != nil {
		return fmt.Errorf("desec: present %s: %w", ch.ResolvedFQDN, err)
	}
	klog.V(1).Infof("presented %s in %s", subName, domain)
	return nil
}

// CleanUp removes only this challenge's key, and the RRset once it is empty.
func (c *desecDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()
	api, domain, subName, err := c.target(ctx, ch)
	if err != nil {
		return err
	}
	value := quote(ch.Key)

	existing, err := api.Records.Get(ctx, domain, subName, "TXT")
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("desec: read %s: %w", ch.ResolvedFQDN, err)
	}
	remaining := slices.DeleteFunc(slices.Clone(existing.Records), func(r string) bool { return r == value })
	switch {
	case len(remaining) == len(existing.Records):
		return nil
	case len(remaining) == 0:
		err = api.Records.Delete(ctx, domain, subName, "TXT")
	default:
		_, err = api.Records.Update(ctx, domain, subName, "TXT", desec.RRSet{Records: remaining})
	}
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("desec: clean up %s: %w", ch.ResolvedFQDN, err)
	}
	klog.V(1).Infof("cleaned up %s in %s", subName, domain)
	return nil
}

// target resolves the deSEC client, domain and subname for a challenge. It only
// ever addresses _acme-challenge names, so a caller-supplied FQDN cannot make
// the webhook write anywhere else in the zone.
func (c *desecDNSProviderSolver) target(ctx context.Context, ch *v1alpha1.ChallengeRequest) (*desec.Client, string, string, error) {
	fqdn := strings.ToLower(util.UnFqdn(ch.ResolvedFQDN))
	if !strings.HasPrefix(fqdn, challengeLabel+".") {
		return nil, "", "", fmt.Errorf("desec: refusing %q: not an %s name", ch.ResolvedFQDN, challengeLabel)
	}

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, "", "", err
	}
	token, err := c.secretKey(ctx, cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, "", "", err
	}
	api := desec.New(token, desec.NewDefaultClientOptions())
	if c.baseURL != "" {
		api.BaseURL = c.baseURL
	}

	domain, err := api.Domains.GetResponsible(ctx, fqdn)
	if err != nil {
		return nil, "", "", fmt.Errorf("desec: no domain owns %s: %w", fqdn, err)
	}
	subName, ok := strings.CutSuffix(fqdn, "."+domain.Name)
	if !ok || (subName != challengeLabel && !strings.HasPrefix(subName, challengeLabel+".")) {
		return nil, "", "", fmt.Errorf("desec: %s is not a challenge name under %s", fqdn, domain.Name)
	}
	return api, domain.Name, subName, nil
}

func loadConfig(cfgJSON *extapi.JSON) (desecDNSProviderConfig, error) {
	cfg := desecDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, errors.New("desec: solver config with apiKeySecretRef is required")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("desec: decoding solver config: %w", err)
	}
	if cfg.APIKeySecretRef.Name == "" || cfg.APIKeySecretRef.Key == "" {
		return cfg, errors.New("desec: apiKeySecretRef needs name and key")
	}
	return cfg, nil
}

func (c *desecDNSProviderSolver) secretKey(ctx context.Context, ref v1.SecretKeySelector, namespace string) (string, error) {
	sec, err := c.client.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("desec: secret %s/%s: %w", namespace, ref.Name, err)
	}
	data, ok := sec.Data[ref.Key]
	if !ok || len(data) == 0 {
		return "", fmt.Errorf("desec: key %q missing in secret %s/%s", ref.Key, namespace, ref.Name)
	}
	return strings.TrimSpace(string(data)), nil
}

func quote(key string) string {
	return `"` + key + `"`
}

func isNotFound(err error) bool {
	var apiErr *desec.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}
