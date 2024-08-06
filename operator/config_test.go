package operator

import (
	"os"
	"reflect"
	"testing"
)

func Test_loadDefaultConfigFromFile(t *testing.T) {
	type args struct {
		config string
	}
	tests := []struct {
		name    string
		args    args
		want    *fileConfig
		wantErr bool
	}{
		{
			"default",
			args{``},
			&fileConfig{
				KubernetesAuthBackend: "kubernetes",
				MetricsAddress:        ":8080",
				Prefix:                "vkcc",
				AWS: awsFileConfig{
					DefaultTTL: 900000000000,
					MinTTL:     900000000000,
					Path:       "aws",
					Rules:      AWSRules(nil),
				},
				GCP: gcpFileConfig{
					Path:  "gcp",
					Rules: GCPRules(nil),
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadConfigFromFile("")
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfigFromFile()\ngotErr: %v\nwantErr:%v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadConfigFromFile()\ngot: %v\nwant:%v", got, tt.want)
			}
		})
	}
}

func Test_loadAWSConfigFromFile(t *testing.T) {
	tmpConf, err := os.CreateTemp("", "vault-kube-cloud-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpConf.Close()
	defer os.Remove(tmpConf.Name())

	type args struct {
		config string
	}
	tests := []struct {
		name    string
		args    args
		want    *fileConfig
		wantErr bool
	}{
		{
			"customAWSConfig",
			args{`
metricsAddress:  ":8081"
prefix: test-1
aws:
  defaultTTL: 1h
  minTTL: 30m
  rules:
    - namespacePatterns:
        - kube-system
        - sys-*
      roleNamePatterns:
        - system-*
      accountIDs:
        - "123456789"
`},
			&fileConfig{
				KubernetesAuthBackend: "kubernetes",
				MetricsAddress:        ":8081",
				Prefix:                "test-1",
				AWS: awsFileConfig{
					DefaultTTL: 3600000000000,
					MinTTL:     1800000000000,
					Path:       "aws",
					Rules: AWSRules{
						AWSRule{
							NamespacePatterns: []string{
								"kube-system",
								"sys-*",
							},
							RoleNamePatterns: []string{"system-*"},
							AccountIDs:       []string{"123456789"},
						},
					},
				},
				GCP: gcpFileConfig{
					Path:  "gcp",
					Rules: GCPRules(nil),
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.OpenFile(tmpConf.Name(), os.O_WRONLY|os.O_TRUNC, 0777)
			if err != nil {
				t.Fatal(err)
			}

			file.WriteString(tt.args.config)
			file.Close()

			got, err := loadConfigFromFile(tmpConf.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfigFromFile()\ngotErr: %v\n wantErr:%v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadConfigFromFile()\ngot: %v\nwant:%v", got, tt.want)
			}
		})
	}
}

func Test_loadGCPConfigFromFile(t *testing.T) {
	tmpConf, err := os.CreateTemp("", "vault-kube-cloud-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpConf.Close()
	defer os.Remove(tmpConf.Name())

	type args struct {
		config string
	}
	tests := []struct {
		name    string
		args    args
		want    *fileConfig
		wantErr bool
	}{
		{
			"customGCPConfig",
			args{`
metricsAddress: ":8081"
prefix: test-1
gcp:
  rules:
    - namespacePatterns:
        - kube-system
      serviceAccountEmailPatterns:
        - foo@bar.iam.gserviceaccount.com
        - baz*@foo.iam.gserviceaccount.com
`},
			&fileConfig{
				KubernetesAuthBackend: "kubernetes",
				MetricsAddress:        ":8081",
				Prefix:                "test-1",
				AWS: awsFileConfig{
					DefaultTTL: 900000000000,
					MinTTL:     900000000000,
					Path:       "aws",
					Rules:      AWSRules(nil),
				},
				GCP: gcpFileConfig{
					Path: "gcp",
					Rules: GCPRules{
						GCPRule{
							NamespacePatterns: []string{"kube-system"},
							ServiceAccEmailPatterns: []string{
								"foo@bar.iam.gserviceaccount.com",
								"baz*@foo.iam.gserviceaccount.com",
							},
						},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := os.OpenFile(tmpConf.Name(), os.O_WRONLY|os.O_TRUNC, 0777)
			if err != nil {
				t.Fatal(err)
			}

			file.WriteString(tt.args.config)
			file.Close()

			got, err := loadConfigFromFile(tmpConf.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfigFromFile()\ngotErr: %v\nwantErr:%v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadConfigFromFile()\ngot: %v\nwant:%v", got, tt.want)
			}
		})
	}
}
