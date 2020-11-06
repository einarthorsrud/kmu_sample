/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <sys/printk.h>
#include <string.h>
#include "nrf_cc3xx_platform.h"
#include "nrf_cc3xx_platform_kmu.h"
#include "mbedtls/cc3xx_kmu.h"
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"

/*
Write key to KMU.

Write key to KMU slot and configure the slot to be non-readable, non-writable
and pushable to the CryptoCell AES key register.

This typically happens in a production image, and this key should never exist
in the product when it is out in the field, as that would compromise the key.
*/
int store_key_in_kmu(uint32_t slot_id)
{
	int ret;

	uint8_t key[16] =
	{
		0x8b, 0xe8, 0xf0, 0x86, 0x9b, 0x3c, 0x0b, 0xa9,
		0x7b, 0x71, 0x86, 0x3d, 0x1b, 0x9f, 0x78, 0x13
	};

	ret = nrf_cc3xx_platform_kmu_write_key_slot(
		slot_id,
		NRF_CC3XX_PLATFORM_KMU_AES_ADDR,
		NRF_CC3XX_PLATFORM_KMU_DEFAULT_PERMISSIONS,
		key);
	if (ret != NRF_CC3XX_PLATFORM_SUCCESS)
	{
		printk("Could not write KMU slot %i. Try erasing the board...\n", slot_id);
		return -1;
	}

	return 0;
}


/*
Demonstrate usage of KMU key for AES-ECB encryption and decryption.
*/
int use_key_from_kmu(uint32_t slot_id)
{
	int ret;

	// Plaintext: abcdefghijklmnop
	uint8_t plain_text[16] =
	{
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70
	};

	// Ciphertext: fd671e1dc1aca49124704502ea716dba
	uint8_t cipher_expected[16] =
	{
		0xfd, 0x67, 0x1e, 0x1d, 0xc1, 0xac, 0xa4, 0x91,
		0x24, 0x70, 0x45, 0x02, 0xea, 0x71, 0x6d, 0xba
	};

	uint8_t cipher_text[16] = {0};
	uint8_t plain_text_decrypted[16] = {0};

	mbedtls_aes_context ctx = {0};
	mbedtls_aes_init(&ctx);

	// Set to use direct shadow key for encryption.
	ret = mbedtls_aes_setkey_enc_shadow_key(&ctx, slot_id, 128);
	if (ret != 0)
	{
		printk("Could not set shadow KMU ECB encrypt key.\n");
		return -1;
	}
	mbedtls_aes_encrypt(&ctx, plain_text, cipher_text);

	if (memcmp(cipher_text, cipher_expected, 16) != 0)
	{
		printk("Invalid encrypted KMU ECB.\n");
		return -1;
	}

	// Reinitialize context.
	mbedtls_aes_init(&ctx);

	// Set to use direct shadow key for decryption.
	ret = mbedtls_aes_setkey_dec_shadow_key(&ctx, slot_id, 128);
	if (ret != 0)
	{
		printk("Could not set shadow KMU ECB encrypt key.\n");
		return -1;
	}

	mbedtls_aes_decrypt(&ctx, cipher_text, plain_text_decrypted);

	if (memcmp(plain_text, plain_text_decrypted, 16) != 0)
	{
		printk("Invalid encrypted KMU ECB.\n");
		return -1;
	}

	return 0;
}


int main(void)
{
	const uint32_t slot_id = 2; // Must be in region 2-127 (0-1 is reseved for KDR).

	printk("KMU sample started.\n");

	if (nrf_cc3xx_platform_init() != 0)
	{
		printk("Failed to initialize CC3xx platform.\n");
		return -1;
	}

	if (store_key_in_kmu(slot_id) == 0)
	{
		printk("Successfully wrote key to KMU slot %i.\n", slot_id);
	}

	if (use_key_from_kmu(slot_id) == 0)
	{
		printk("Successfully encrypted and decrypted data using key from KMU.\n");
	}
	
	return 0;
}
