# clevis-pin-tpm2-signtool
This is a reference tool for the clevis-pin-tpm2's policy signing.

It accepts a yaml input on stdin (see `unsignedpolicy.yaml` for an example), loads the private key (it will create one if it doesn't exist), sign the policy and write the resulting json to stdout.
