/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "KeyContainer"
 * 	found in "KeyContainer.asn1"
 * 	`asn1c -fwide-types -findirect-choice`
 */

#ifndef	_KeyResource_H_
#define	_KeyResource_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CipherKeyResource.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum KeyResource_PR {
	KeyResource_PR_NOTHING,	/* No components present */
	KeyResource_PR_counter
} KeyResource_PR;

/* KeyResource */
typedef struct KeyResource {
	KeyResource_PR present;
	union KeyResource_u {
		CipherKeyResource_t	 counter;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} KeyResource_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_KeyResource;

#ifdef __cplusplus
}
#endif

#endif	/* _KeyResource_H_ */
#include <asn_internal.h>