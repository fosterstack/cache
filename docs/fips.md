# FIPS 140-3

The fscache-fips build uses the Go Cryptographic Module, validated to FIPS 140-3 under CMVP certificate #5247, with FIPS mode on by default. The certificate's vendor-affirmed operating environments include Linux on x86-64 and ARM64, where our images run, so the module keeps its validation inside our images. [SC-13 sentence pending]

The validation covers the cryptographic module. It does not cover FosterStack Cache as a whole, and FedRAMP or any other program attaches to your service, not to a component you deploy.

## Check it yourself

The `-fips` build reports its status at startup and on `/statusz`:

```
"fips140":"active (Go validated module v1.0.0, CMVP cert #5247)"
```

Standard builds report `"fips140":"off"`. The `/statusz` page carries the same text as `fips140_note`.

- [Certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247) at NIST.
- [Security Policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf): Table 4 lists the vendor-affirmed operating environments, including Linux 3.10 and later on x86-64 and ARM.
- [Go's FIPS 140-3 page](https://go.dev/doc/security/fips140).

## Questions

**Our operating system is not in the certificate's tested list. Is the module still validated there?**
Yes. A software module's certificate lists the systems the lab tested on. Under the CMVP's porting rules, an unmodified software module stays compliant with its validation on any general-purpose platform that runs a listed or compatible operating system (CMVP Management Manual, section 7.9, "Vendor or User Affirmation of Modules"). The Security Policy also lists Linux on x86-64 and ARM as vendor-affirmed, which covers our images.
