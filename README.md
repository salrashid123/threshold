## Threshold Key Generation and Signing with Google Confidential Space

This repository demonstrates how multiple parties can collectively generate keys and sign using [Threshold cryptosystem](https://en.wikipedia.org/wiki/Threshold_cryptosystem) running on Google Cloud Platforms's [Confidential Space](https://cloud.google.com/docs/security/confidential-space).

There are two components that use Confidential Space in slightly different ways:

* `Generate`:  This will generate and distribute threshold signing keys to `N` remote parties where the keys can participate in a [BLS digital signatures](https://en.wikipedia.org/wiki/BLS_digital_signature).  In other words, this will securely create and distribute keys. Each participant does not need be a GCP customer but the operator that runs the 'server' necessarily needs to run on GCP.

* `Sign`:  This will take a subset `t` of those `n` participants partial signatures to create a combined signature that represents the group signature 

Both steps are nothing new: there are lots of academic and libraries that do both steps here which is referenced below in the `Background` section.   In other words, this will securely acquire and combine partial signatures.  Each participant and operator needs to be a GCP customer.

---

The protocol and procedure here utilizes `Google Cloud Confidential Space` as a intermediary to broker the key generation and signing steps in a way that the ultimate trust is based on an attestation provided by nature of that very product.

While this protocol still involves third party for the steps, the critical difference is that each participant will _know_ the operations at each step was ultimately executed using code the know is performing the expected task.

The protocols outlined below uses certain unique capabilities and verifiable attestations claims as proof of code integrity and operations within a Confidential Space VM.

GCP `Confidential Space` is a service offering from google where a specific user-defined docker container runs within a restricted, sandboxed VM where not even the cloud operator or provider can access.

Confidential Space can [issue proofs](https://cloud.google.com/docs/security/confidential-space#protecting-workload) that on face value assert:

* VM is ONLY running a specific container `image_hash`
* VM is using memory Encryption (AMD SEV)
* No ssh serial access is allowed to the VM
* Cloud Operator cannot issue attestation token claiming a specific image hash and GCP Project other than from within that very Confidential Space VM

Confidential space VMs can internally issue a Signed/Verifiable JWT attestation token rooted to google within which there are claims asserting the states mentioned above.  These tokens also happen to be OIDC tokens compatible for authentication to GCP via [Workload Federation](https://cloud.google.com/iam/docs/workload-identity-federation).

In addition, any client that is connecting to the TEE can recieve assurances/attestation that it is connecting _TO_ the TEE with those given specifications.  In other words, each client will know at the TLS level that it is infact talking to a TEE running a trusted codebase.

Essentially, this technique creates a client-server system where the server will either generate keys or sign and the client represents each participant.  

The critical aspects in this flow:

1. the code is opensourced so all participants can review code to make sure it is doing just what is intended (eg, either sign or generate)
2. the code in 1 is generated using `bazel` to build a specific image hash.  In other words, a container image for the code in `1` will always produce the same sha256 image hash no matter where it is built.  If any participant wants to, they can build the same image from opensource and arrive at the same image hahs.
3. The confidential VM runs the container image hash specified in 2.
4. Each participant for signing or key generation receives live attestations from the server asserting that the VM is infact running in Confidential Space with the image hash declared in step 3.  The attestation also confirms no ssh access is possible.
5. Participants can use the attestation JWT to also confirm at a TLS connection level that they are connecting to that specific VM.  This is described later and is facilitated by the TLS `Exported Key Material (EKM)`

Given the chained confirmation steps described above, a participant/client can interact with the server in a way that at each step, they know that ultimately they are interacting with a specific image hash within confidential space since they will recieve said attestation.

You can read more about `Confidential Space` and `Bazel` build systems here:

* [Constructing Trusted Execution Environment (TEE) with GCP Confidential Space](https://github.com/salrashid123/confidential_space)
* [Deterministic builds with go + bazel + grpc + docker](https://github.com/salrashid123/go-grpc-bazel-docker)

---

### Background

As background, generating and signing threshold keys is relatively well documented academically and there are even several [libraries](https://pkg.go.dev/go.dedis.ch/kyber) users can employ to do the same.  For more references, see:

* [Walking Through Distributed Key Generation (DKG)](https://hackmd.io/@thor314/ryEW5m2V9)
* [Distributed Key Generation](https://en.wikipedia.org/wiki/Distributed_key_generation)
* [A Threshold Cryptosystem without a Trusted Party](https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf)
* [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://link.springer.com/content/pdf/10.1007/s00145-006-0347-3.pdf)
* [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf)
* [Verifiable Secret Sharing](https://en.wikipedia.org/wiki/Verifiable_secret_sharing)

However, the practical mechanisms on how users go about generating and signing is fairly convoluted and approach the issue from an academic perspective without leveraging modern cloud technologies.

- for threshold key generation you either need a trusted party or multi-step peer-peer rounds communication where exchanges of proofs and temporary, partial keys are involved

- for threshold signing, you would either need to generate partial signatures locally by each participant and aggregated together by a 3rd actor or enable a trusted 3rd party service to acquire raw keys security and perform the signature.

* [Improvements on Distributed KeyGeneration cryptography](https://www.epfl.ch/labs/dedis/wp-content/uploads/2020/01/report-2018_1-kopiga_rasiah-dkg.pdf)
* [Distributed key generation (DKG) using FROST threshold Schnorr signature protocol in Kryptology](https://asecuritysite.com/kryptology/dkg)
* [Distributed key generation](https://en.wikipedia.org/wiki/Distributed_key_generation)
* [Threshold cryptosystem](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
* [Threshold Digital Signatures](https://www.coinbase.com/blog/threshold-digital-signatures)
* [Threshold Signatures Explained](https://academy.binance.com/en/articles/threshold-signatures-explained)

---

### Contents

Anyway, you can find samples for generation and signing here:

* [Generate](generate/#generate)
  - [Server](generate/#generate-server)
  - [Client](generate/#generate-client)  
* [Sign](sign/#sign)
  - [Server](sign/#sign-server)
  - [Client](sign/#sign-client)  

