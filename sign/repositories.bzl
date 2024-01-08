load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "ch_dedis_go_fixbuf",
        importpath = "go.dedis.ch/fixbuf",
        sum = "h1:hGcV9Cd/znUxlusJ64eAlExS+5cJDIyTyEG+otu5wQs=",
        version = "v1.0.3",
    )
    go_repository(
        name = "ch_dedis_go_kyber_v3",
        importpath = "go.dedis.ch/kyber/v3",
        sum = "h1:FDuC/S3STkvwxZ0ooo3gcp56QkUKsN7Jy7cpzBxL+vQ=",
        version = "v3.0.4",
    )
    go_repository(
        name = "ch_dedis_go_kyber_v4",
        importpath = "go.dedis.ch/kyber/v4",
        sum = "h1:+KMfT7P/+KOfeYge3tY3JrnJXka8NwQacaL+BFkRts8=",
        version = "v4.0.0-pre2",
    )
    go_repository(
        name = "ch_dedis_go_protobuf",
        importpath = "go.dedis.ch/protobuf",
        sum = "h1:wRUEiq3u0/vBhLjcw9CmAVrol+BnDyq2M0XLukdphyI=",
        version = "v1.0.7",
    )

    go_repository(
        name = "com_github_davecgh_go_spew",
        importpath = "github.com/davecgh/go-spew",
        sum = "h1:U9qPSI2PIWSS1VwoXQT9A3Wy9MM3WgvqSxFWenqJduM=",
        version = "v1.1.2-0.20180830191138-d8f796af33cc",
    )
    go_repository(
        name = "com_github_golang_glog",
        importpath = "github.com/golang/glog",
        sum = "h1:uCdmnmatrKCgMBlM4rMuJZWOkPDqdbZPnrMXDY4gI68=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_golang_jwt_jwt_v5",
        importpath = "github.com/golang-jwt/jwt/v5",
        sum = "h1:d/ix8ftRUorsN+5eMIlF4T6J8CAt9rch3My2winC1Jw=",
        version = "v5.2.0",
    )
    go_repository(
        name = "com_github_google_go_cmp",
        importpath = "github.com/google/go-cmp",
        sum = "h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=",
        version = "v0.6.0",
    )

    go_repository(
        name = "com_github_google_uuid",
        importpath = "github.com/google/uuid",
        sum = "h1:1p67kYwdtXjb0gL0BPiP1Av9wiZPo5A8z2cWkTZ+eyU=",
        version = "v1.5.0",
    )
    go_repository(
        name = "com_github_gorilla_mux",
        importpath = "github.com/gorilla/mux",
        sum = "h1:TuBL49tXwgrFYWhqrNgrUNEY92u81SPhu7sTdzQEiWY=",
        version = "v1.8.1",
    )
    go_repository(
        name = "com_github_hashicorp_golang_lru_v2",
        importpath = "github.com/hashicorp/golang-lru/v2",
        sum = "h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k=",
        version = "v2.0.7",
    )
    go_repository(
        name = "com_github_lestrrat_go_jwx",
        importpath = "github.com/lestrrat/go-jwx",
        sum = "h1:LbObMwh+lyWzIyVMd7iqsv1Az4EJDO0hURuSP1BFZcU=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_lestrrat_go_pdebug",
        importpath = "github.com/lestrrat/go-pdebug",
        sum = "h1:ttJD8hTqvrPEUBoAG5hJKbDOJ84u7zmbnZsUL4V9430=",
        version = "v0.0.0-20180220043741-569c97477ae8",
    )
    go_repository(
        name = "com_github_pkg_errors",
        importpath = "github.com/pkg/errors",
        sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_pmezard_go_difflib",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:Jamvg5psRIccs7FGNTlIRMkT8wgtp5eCXdBlqhYGL6U=",
        version = "v1.0.1-0.20181226105442-5d4384ee4fb2",
    )
    go_repository(
        name = "com_github_salrashid123_confidential_space_claims",
        importpath = "github.com/salrashid123/confidential_space/claims",
        sum = "h1:YagiF9q9jI6wwNnAPor3OuzBmgNC/C7/+cMsHHXQLTA=",
        version = "v0.0.0-20231220005054-10142ffa42ab",
    )
    go_repository(
        name = "com_github_salrashid123_confidential_space_misc_testtoken",
        importpath = "github.com/salrashid123/confidential_space/misc/testtoken",
        sum = "h1:WGcDOaXiF/aQWNtPkKlaDziejtaY7Qn54Zxn5FO1MqY=",
        version = "v0.0.0-20240102144154-40dc017c01b7",
    )
    go_repository(
        name = "com_github_stretchr_objx",
        importpath = "github.com/stretchr/objx",
        sum = "h1:1zr/of2m5FGMsad5YfcqgdqdWrIhu+EBEJRhR1U7z/c=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_stretchr_testify",
        importpath = "github.com/stretchr/testify",
        sum = "h1:CcVxjf3Q8PM0mHUKJCdn+eZZtm5yQwehR5yeSVQQcUk=",
        version = "v1.8.4",
    )
    go_repository(
        name = "in_gopkg_yaml_v3",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
        version = "v3.0.1",
    )
    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        sum = "h1:wBqGXzWJW6m1XrIKlAH0Hs1JJ7+9KBwnIO8v66Q9cHc=",
        version = "v0.14.0",
    )
    go_repository(
        name = "org_golang_x_mod",
        importpath = "golang.org/x/mod",
        sum = "h1:LUYupSeNrTNCGzR/hVBk2NHZO4hXcVaW1k4Qx7rjPx8=",
        version = "v0.8.0",
    )
    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:7eBu7KsSvFDtSXUIDbh3aqlK4DPsZ1rByC8PFfBThos=",
        version = "v0.16.0",
    )
    go_repository(
        name = "org_golang_x_sys",
        importpath = "golang.org/x/sys",
        sum = "h1:Af8nKPmuFypiUBjVoU9V20FiaFXOcuZI21p0ycVYYGE=",
        version = "v0.13.0",
    )
    go_repository(
        name = "org_golang_x_term",
        importpath = "golang.org/x/term",
        sum = "h1:bb+I9cTfFazGW51MZqBVmZy7+JEJMouUHTUSKVQLBek=",
        version = "v0.13.0",
    )
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=",
        version = "v0.14.0",
    )
    go_repository(
        name = "org_golang_x_tools",
        importpath = "golang.org/x/tools",
        sum = "h1:BOw41kyTf3PuCW1pVQf8+Cyg8pMlkYB1oo9iJ6D/lKM=",
        version = "v0.6.0",
    )