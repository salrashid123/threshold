module github.com/salrashid123/threshold/generate

go 1.21

toolchain go1.21.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/golang/glog v1.2.0
	github.com/google/uuid v1.3.1
	github.com/gorilla/mux v1.8.1
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/hashicorp/vault/sdk v0.10.2
	github.com/lestrrat/go-jwx v0.9.1
	github.com/salrashid123/confidential_space/claims v0.0.0-20231220005054-10142ffa42ab
	github.com/salrashid123/confidential_space/misc/testtoken v0.0.0-20240102144154-40dc017c01b7
	github.com/salrashid123/threshold/generate/common v0.0.0-00010101000000-000000000000
	go.dedis.ch/kyber/v4 v4.0.0-pre2
	golang.org/x/exp v0.0.0-20231226003508-02704c960a9b
	golang.org/x/net v0.16.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	go.dedis.ch/protobuf v1.0.11 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/salrashid123/threshold/generate/common => ./common
