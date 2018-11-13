#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define MAKE_RUST_SGX_TYPE(sgxtype) typedef struct r_##sgxtype { \
                                        intptr_t handle; \
                                        char *mr_enclave; \
                                        char *basename; \
                                    }r_##sgxtype;

//MAKE_RUST_SGX_TYPE(sgx_signup_info_t);
MAKE_RUST_SGX_TYPE(sgx_enclave_id_t);

typedef struct r_sgx_signup_info_t {
    intptr_t handle;
    char *poet_public_key;
    uint32_t poet_public_key_len;
    char *enclave_quote;
    //char *proof_data;
    //char *anti_sybil_id;
}r_sgx_signup_info_t;

typedef struct r_sgx_wait_certificate_t {
    intptr_t handle;
	char *ser_wait_cert;
	char *ser_wait_cert_sign;
}r_sgx_wait_certificate_t;

typedef struct r_sgx_epid_group_t {
    char *epid;
}r_sgx_epid_group_t;


#ifdef __cplusplus
extern "C" {
#endif

int r_initialize_enclave(r_sgx_enclave_id_t *eid, const char *enclave_path, 
                         const char *spid);

int r_free_enclave(r_sgx_enclave_id_t *eid);

int r_get_epid_group(r_sgx_enclave_id_t *eid, r_sgx_epid_group_t *epid_group);

bool r_is_sgx_simulator(r_sgx_enclave_id_t *eid);

int r_set_signature_revocation_list(r_sgx_enclave_id_t *eid, const char *sig_revocation_list);

int r_create_signup_info(r_sgx_enclave_id_t *eid, const char *opk_hash, 
                        r_sgx_signup_info_t *signup_info);

int r_release_signup_info(r_sgx_enclave_id_t *eid, r_sgx_signup_info_t *signup_info);

int r_initialize_wait_certificate(r_sgx_enclave_id_t *eid, uint8_t* duration, 
                                    const char* prev_wait_cert, const char* prev_wait_cert_sig,
                                    const char* validator_id, const char* poet_pub_key);

int r_finalize_wait_certificate(r_sgx_enclave_id_t *eid, r_sgx_wait_certificate_t *wait_cert,
                                const char *prev_wait_cert, 
                                const char *prev_block_id, const char *prev_wait_cert_sig,
                                const char *block_summary, uint64_t wait_time);

bool r_verify_wait_certificate(r_sgx_enclave_id_t *eid, const char *ppk,
                               const char *wait_cert, const char *wait_cert_sign); 

int r_release_wait_certificate(r_sgx_enclave_id_t *eid, r_sgx_wait_certificate_t *wait_cert);

#ifdef __cplusplus
}
#endif

