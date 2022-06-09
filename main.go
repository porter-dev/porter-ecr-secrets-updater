package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
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

	awsAccessKeyID     = ""
	awsSecretAccessKey = ""
	awsSessionToken    = ""
)

func main() {
	flag.StringVar(&awsAccessKeyID, "aws_access_key_id", "", "the AWSAccessKeyId to use")
	flag.StringVar(&awsSecretAccessKey, "aws_secret_access_key", "", "the AWSSecretKey to use")
	flag.StringVar(&awsSessionToken, "aws_session_token", "", "(optional) required for temporary security credentials retrieved via STS")

	flag.Parse()

	if awsAccessKeyID == "" || awsSecretAccessKey == "" {
		log.Fatalln("'aws_access_key_id' and 'aws_secret_access_key' are required flags")
	}

	config, err := rest.InClusterConfig()

	if err != nil {
		log.Fatalln(err)
	}

	clientset := kubernetes.NewForConfigOrDie(config)

	var namespaces []string
	var continueStr string

	for {
		namespaceList, err := clientset.CoreV1().Namespaces().List(
			context.Background(), metav1.ListOptions{
				Limit:    100,
				Continue: continueStr,
			},
		)

		if err != nil {
			log.Fatalln(err)
		}

		for _, ns := range namespaceList.Items {
			namespaces = append(namespaces, ns.GetName())
		}

		if namespaceList.Continue == "" {
			break
		}

		continueStr = namespaceList.Continue
	}

	var pods []v1.Pod
	continueStr = ""

	for _, ns := range namespaces {
		podList, err := clientset.CoreV1().Pods(ns).List(
			context.Background(), metav1.ListOptions{
				Limit:    100,
				Continue: continueStr,
			},
		)

		if err != nil {
			log.Fatalln(err)
		}

		pods = append(pods, podList.Items...)

		if podList.Continue == "" {
			break
		}

		continueStr = podList.Continue
	}

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

				secret, err := clientset.CoreV1().Secrets(pod.GetNamespace()).Get(
					context.Background(), pullSecret.Name, metav1.GetOptions{},
				)

				if err != nil {
					log.Fatalln(err)
				}

				prevData, exists := secret.Data[v1.DockerConfigJsonKey]

				if !exists {
					continue
				}

				sess, err := getAWSSession(matches[3])

				if err != nil {
					log.Fatalln(err)
				}

				dockerConfigFile, err := getDockerConfigFile(sess, regURL)

				if err != nil {
					log.Fatalln(err)
				}

				newData, err := json.Marshal(dockerConfigFile)

				if err != nil {
					log.Fatalln(err)
				}

				if !bytes.Equal(prevData, newData) {
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
						log.Fatalln(err)
					}
				}
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
