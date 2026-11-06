# FIPS 140-3

The fscache-fips build uses the Go Cryptographic Module, validated to FIPS 140-3 under CMVP certificate #5247, with FIPS mode on by default. The certificate's vendor-affirmed operating environments include Linux on x86-64 and ARM64, where our images run, so the module keeps its validation inside our images. That gives you a FIPS-validated cryptographic module for control SC-13 in the NIST SP 800-53B low, moderate and high baselines (FedRAMP Low, Moderate and High), where FedRAMP accepts FIPS-validated modules.

The validation covers the cryptographic module. It does not cover FosterStack Cache as a whole, and FedRAMP or any other program attaches to your service, not to a component you deploy.

## Check it yourself

The `-fips` build reports its status in the startup log:

```
"fips140":"active (Go validated module ..., CMVP cert ...)"
```

The dots stand for the module version and the certificate number. On `/statusz` the same text is in `fips140_note`, next to `"fips140":true`. A standard build reports `"fips140":"off"` at startup and `"fips140":false` on `/statusz`. If FIPS mode is forced on in a standard build (`GODEBUG=fips140=on`), the note says it is not the validated-module build.

- [Certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247) at NIST.
- [Security Policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf): Table 4 lists the vendor-affirmed operating environments, including Linux 3.10 and later on x86-64 and ARM.
- [Go's FIPS 140-3 page](https://go.dev/doc/security/fips140).

## Questions

**Our operating system is not in the certificate's tested list. Is the module still validated there?**
Yes. The certificate's tested list names the systems the lab tested on. Under the CMVP's porting rules, the vendor or the user may affirm that an unmodified software module remains compliant with its validation on any general-purpose platform that runs a listed or compatible operating system (CMVP Management Manual, section 7.9, "Vendor or User Affirmation of Modules"). For Linux on x86-64 and ARM64, where our images run, the vendor's affirmation is already in the Security Policy (Table 4).
