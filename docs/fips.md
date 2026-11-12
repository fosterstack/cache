# FIPS 140-3

The fscache-fips build uses the Go Cryptographic Module, validated to FIPS 140-3 under [CMVP certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247), with FIPS mode on by default. We build the module unmodified, the way its [Security Policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf) says to, and the Security Policy lists Linux on x86-64 and ARM64 as vendor-affirmed operating environments, which is where our images run. So our images are "FIPS 140-3 Inside, Certificate #5247", for the module when operated in approved mode (the certificate's condition). The image turns FIPS mode on by default and does not force approved-only use: the module is in approved mode while the calls made use approved services (Security Policy, section 2.4). One limit applies. The CMVP says: "CMVP makes no statement as to the correct operation of the module or the security strengths of the generated keys when so ported if the specific operational environment is not listed on the validation certificate." Our base operating system, Wolfi, is not listed in the Security Policy.

The validation covers the cryptographic module. It does not cover FosterStack Cache as a whole.

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

**Our operating system is not in the Security Policy's tested list. Is the module still validated there?**
The limit stated at the top applies. Under the CMVP's porting rules, the vendor or the user may affirm that an unmodified software module remains compliant on any general-purpose platform that runs a listed or compatible operating system (CMVP Management Manual, section 7.9, "Vendor or User Affirmation of Modules"). For Linux on x86-64 and ARM64, where our images run, the vendor's affirmation is already in the Security Policy (Table 4).
