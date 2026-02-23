#!/bin/bash
# Generate RSA signing keys for SGX enclave signing (development/testing only)
# In production, use Intel's provisioning process with proper key management.

set -e

KEY_SIZE=3072

echo "Generating SGX enclave signing keys..."

openssl genrsa -out server/EnclaveResponder/EnclaveResponder_private_test.pem $KEY_SIZE
openssl genrsa -out client/EnclaveInitiator/EnclaveInitiator_private_test.pem $KEY_SIZE
openssl genrsa -out client/EnclaveExecutor/EnclaveExecutor_private_test.pem $KEY_SIZE
openssl genrsa -out user/EnclaveInitiator/EnclaveInitiator_private_test.pem $KEY_SIZE

echo "Done. Keys generated:"
echo "  - server/EnclaveResponder/EnclaveResponder_private_test.pem"
echo "  - client/EnclaveInitiator/EnclaveInitiator_private_test.pem"
echo "  - client/EnclaveExecutor/EnclaveExecutor_private_test.pem"
echo "  - user/EnclaveInitiator/EnclaveInitiator_private_test.pem"
echo ""
echo "WARNING: These keys are for development/testing only."
echo "         Never use them in production."
