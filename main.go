package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	ecrPattern = regexp.MustCompile(`(^[a-zA-Z0-9][a-zA-Z0-9-_]*)\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.amazonaws\.com(\.cn)?`)

	awsAccessKeyID     = os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsSessionToken    = os.Getenv("AWS_SESSION_TOKEN")
)

func main() {
	if awsAccessKeyID == "" || awsSecretAccessKey == "" {
		log.Fatalln("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required environment variables and must be set")
	}

	config, err := rest.InClusterConfig()

	if err != nil {
		log.Fatalln(fmt.Errorf("error getting in-cluster config: %w", err))
	}

	clientset := kubernetes.NewForConfigOrDie(config)

	var namespaces []string
	var continueStr string

	log.Println("fetching list of namespaces in this cluster")

	for {
		namespaceList, err := clientset.CoreV1().Namespaces().List(
			context.Background(), metav1.ListOptions{
				Limit:    100,
				Continue: continueStr,
			},
		)

		if err != nil {
			log.Fatalln(fmt.Errorf("error fetching list of namespaces: %w", err))
		}

		for _, ns := range namespaceList.Items {
			namespaces = append(namespaces, ns.GetName())
		}

		if namespaceList.Continue == "" {
			break
		}

		continueStr = namespaceList.Continue
	}

	log.Printf("fetched %d namespaces\n", len(namespaces))

	var pods []v1.Pod
	continueStr = ""

	log.Println("fetching list of pods in all namespaces in this cluster")

	for _, ns := range namespaces {
		for {
			podList, err := clientset.CoreV1().Pods(ns).List(
				context.Background(), metav1.ListOptions{
					Limit:    100,
					Continue: continueStr,
				},
			)

			if err != nil {
				log.Fatalln(fmt.Errorf("error fetching list of pods for namespace %s: %w", ns, err))
			}

			pods = append(pods, podList.Items...)

			if podList.Continue == "" {
				break
			}

			continueStr = podList.Continue
		}
	}

	log.Printf("fetched %d pods across all namespaces\n", len(pods))

	checked := make(map[string]bool)

	for _, pod := range pods {
		podSpec := pod.Spec

		for _, container := range podSpec.Containers {
			regURL := strings.Split(container.Image, ":")[0]
			matches := ecrPattern.FindStringSubmatch(regURL)

			if len(matches) < 3 || len(podSpec.ImagePullSecrets) == 0 {
				continue
			}

			for _, pullSecret := range podSpec.ImagePullSecrets {
				if !strings.HasPrefix(pullSecret.Name, "porter-ecr") {
					continue
				}

				checkedMapEntryKey := fmt.Sprintf("%s:%s", pullSecret.Name, pod.GetNamespace())

				if _, ok := checked[checkedMapEntryKey]; ok {
					// already checked and possibly updated secret
					continue
				}

				log.Printf("found pod '%s' in namespace '%s' with ECR secret '%s' to possibly update",
					pod.GetName(), pod.GetNamespace(), pullSecret.Name)

				secret, err := clientset.CoreV1().Secrets(pod.GetNamespace()).Get(
					context.Background(), pullSecret.Name, metav1.GetOptions{},
				)

				if err != nil {
					log.Fatalln(fmt.Errorf("error fetching secret '%s' in namespace '%s': %w",
						pullSecret.Name, pod.GetNamespace(), err))
				}

				prevData, exists := secret.Data[v1.DockerConfigJsonKey]

				if !exists {
					log.Println("no DockerConfigJsonKey found, skipping")

					continue
				}

				sess, err := getAWSSession(matches[3])

				if err != nil {
					log.Fatalln(fmt.Errorf("error getting AWS session: %w", err))
				}

				dockerConfigFile, err := getDockerConfigFile(sess, regURL)

				if err != nil {
					log.Fatalln(fmt.Errorf("error getting docker config file: %w", err))
				}

				newData, err := json.Marshal(dockerConfigFile)

				if err != nil {
					log.Fatalln(fmt.Errorf("error marshalling docker config file JSON data"))
				}

				if !bytes.Equal(prevData, newData) {
					log.Println("updating outdated secret")

					_, err := clientset.CoreV1().Secrets(pod.GetNamespace()).Update(
						context.Background(),
						&v1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Name: pullSecret.Name,
							},
							Data: map[string][]byte{
								string(v1.DockerConfigJsonKey): newData,
							},
							Type: v1.SecretTypeDockerConfigJson,
						},
						metav1.UpdateOptions{},
					)

					if err != nil {
						log.Fatalln(fmt.Errorf("error updating secret: %w", err))
					}
				} else {
					log.Println("no change to the secret required")
				}

				checked[checkedMapEntryKey] = true
			}
		}
	}
}

func getAWSSession(region string) (*session.Session, error) {
	awsConf := &aws.Config{
		Credentials: credentials.NewStaticCredentials(
			awsAccessKeyID,
			awsSecretAccessKey,
			awsSessionToken,
		),
	}

	if region != "" {
		awsConf.Region = aws.String(region)
	}

	return session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *awsConf,
	})
}

func getDockerConfigFile(sess *session.Session, regURL string) (*configfile.ConfigFile, error) {
	ecrSvc := ecr.New(sess)

	output, err := ecrSvc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})

	if err != nil {
		return nil, err
	}

	token := *output.AuthorizationData[0].AuthorizationToken

	decodedToken, err := base64.StdEncoding.DecodeString(token)

	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)

	if len(parts) < 2 {
		return nil, err
	}

	key := regURL

	if !strings.Contains(key, "http") {
		key = "https://" + key
	}

	return &configfile.ConfigFile{
		AuthConfigs: map[string]types.AuthConfig{
			key: {
				Username: parts[0],
				Password: parts[1],
				Auth:     token,
			},
		},
	}, nil
}
