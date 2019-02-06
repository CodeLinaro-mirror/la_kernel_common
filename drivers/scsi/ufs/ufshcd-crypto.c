/*
 * Universal Flash Storage Host controller driver crypto core
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * See the COPYING file in the top-level directory or visit
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This program is provided "AS IS" and "WITH ALL FAULTS" and
 * without warranty of any kind. You are solely responsible for
 * determining the appropriateness of using and distributing
 * the program and assume all risks associated with your exercise
 * of rights with respect to the program, including but not limited
 * to infringement of third party rights, the risks and costs of
 * program errors, damage to or loss of data, programs or equipment,
 * and unavailability or interruption of operations. Under no
 * circumstances will the contributor of this Program be liable for
 * any damages of any kind arising from your use or distribution of
 * this program.
 *
 * The Linux Foundation chooses to take subject only to the GPLv2
 * license terms, and distributes only under these terms.
 */

#include "ufshcd.h"
#include "ufshcd-crypto.h"


/*TODO: worry about endianness and cpu_to_le32 */

bool ufshcd_hba_is_crypto_supported(struct ufs_hba *hba) {
	return hba->crypto_capabilities.reg_val != 0;
}

bool ufshcd_is_crypto_enabled(struct ufs_hba *hba)
{
	return hba->caps & UFSHCD_CAP_CRYPTO;
}

bool crypto_cfg_slot_in_bounds(struct ufs_hba *hba, unsigned int slot) {
	/**
         * The actual number of configurations supported is (CFGC+1), so slot
         * numbers range from 0 to config_count inclusive.
         */
	return slot <= hba->crypto_capabilities.config_count;
}

static int get_ufs_data_mask_for_data_unit_size(unsigned int data_unit_size,
						u8* ufs_data_mask) {
	if (data_unit_size % 512 != 0) {
		return -EINVAL;
	}
	data_unit_size /= 512;

	/* Check that data_unit_size has exactly 1 bit set */
	if ((data_unit_size & (data_unit_size -1)) != 0 ||
	     data_unit_size == 0) {
		return -EINVAL;
	}

	if (data_unit_size > 0xFF) {
		return -EINVAL;
	}

	*ufs_data_mask = (u8)data_unit_size;
	
	return 0;
}

/**
 * ufshcd_crypto_cfg_entry_write_key - Write a key into a crytpo_cfg_entry
 * @cfg: The crypto config to write to
 * @key: The key to write
 * @key_len: The length of the key array
 *
 * Returns 0 for success and non-zero for failure
 */
int ufshcd_crypto_cfg_entry_write_key(union ufs_crypto_cfg_entry *cfg, u8 *key,
				      size_t key_size_bytes,
				      enum ufs_crypto_alg crypto_alg) {
	if (cfg == NULL || key == NULL) {
		return -EINVAL;
	}

	/* All modes only support a subset of these key sizes */
	if (key_size_bytes != 16 && key_size_bytes != 32 &&
		key_size_bytes != 48 && key_size_bytes != 64)
		return -EINVAL;

	switch (crypto_alg) {
		case UFS_CRYPTO_ALG_AES_XTS: {
			/* This mode needs at least 32 bytes of key */
			if (key_size_bytes < 32) {
				return -EINVAL;
			}
			memcpy(cfg->crypto_key, key, key_size_bytes/2);
			memcpy(cfg->crypto_key + 256/8,
			       key + key_size_bytes/2, key_size_bytes/2);
			return 0;
		}
		case UFS_CRYPTO_ALG_BITLOCKER_AES_CBC: // fallthrough
		case UFS_CRYPTO_ALG_AES_ECB: // fallthrough
		case UFS_CRYPTO_ALG_ESSIV_AES_CBC: {
			/* These modes don't support 48 byte keys */
			if (key_size_bytes == 48) {
				return -EINVAL;
			}
			memcpy(cfg->crypto_key, key, key_size_bytes);
			return 0;
		}
		default: return -EINVAL;
	};
	
	return -EINVAL;
}

int ufshcd_crypto_program_key(void *hba_p, u8* key, size_t key_size_bytes,
			      unsigned int data_unit_size, unsigned int cap_idx,
			      unsigned int slot) {
	struct ufs_hba *hba = hba_p;
	int c = 0;
	u8 data_unit_mask;
	union ufs_crypto_cfg_entry cfg;

	if (!ufshcd_is_crypto_enabled(hba) ||
	    !crypto_cfg_slot_in_bounds(hba, slot) ||
	    key_size_bytes > UFS_CRYPTO_KEY_MAX_SIZE ||
	    cap_idx >= hba->crypto_capabilities.num_crypto_cap) {
		return -EINVAL;
	}

	if (get_ufs_data_mask_for_data_unit_size(data_unit_size,
						 &data_unit_mask) != 0) {
		return -EINVAL;
	}
	
	if ((data_unit_mask & hba->crypto_cap_array[cap_idx].sdus_mask) == 0) {
		return -EINVAL;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.data_unit_size = data_unit_mask;
	cfg.crypto_cap_idx = cap_idx;
	cfg.config_enable |= UFS_CRYPTO_CONFIGURATION_ENABLE;

	c = ufshcd_crypto_cfg_entry_write_key(&cfg, key, key_size_bytes,
				hba->crypto_cap_array[cap_idx].algorithm_id);
	if (c != 0) {
		return c;
	}

	/* Write the crypto cfg to device */
	for (c = 0; c < sizeof(cfg)/sizeof(cfg.reg_val[0]); c++) {
		ufshcd_writel(hba, cfg.reg_val[c],
			      hba->crypto_cfg_register +
			      slot * sizeof(cfg) + c * sizeof(cfg.reg_val[0]));
	}
	mb();

	memcpy(&hba->crypto_cfg_array[slot], &cfg, sizeof(cfg));

	return 0;
}

int ufshcd_crypto_find_slot_for_key(void *hba_p, u8 *key, size_t key_size_bytes,
				    unsigned int data_unit_size_bytes, unsigned int cap_idx) {
	struct ufs_hba *hba = hba_p;
	int c = 0;
	u8 data_unit_mask;
	union ufs_crypto_cfg_entry cfg;

	if (!ufshcd_is_crypto_enabled(hba) ||
	    key_size_bytes > UFS_CRYPTO_KEY_MAX_SIZE ||
	    cap_idx >= hba->crypto_capabilities.num_crypto_cap) {
		return -EINVAL;
	}

	if (get_ufs_data_mask_for_data_unit_size(data_unit_size_bytes,
						 &data_unit_mask) != 0) {
		return -EINVAL;
	}

	if ((data_unit_mask & hba->crypto_cap_array[cap_idx].sdus_mask) == 0) {
		return -EINVAL;
	}

	memset(&cfg, 0, sizeof(cfg));
	if (ufshcd_crypto_cfg_entry_write_key(&cfg, key, key_size_bytes,
				hba->crypto_cap_array[cap_idx].algorithm_id) != 0) {
		return -EINVAL;
	}

	for (c = 0; c <= hba->crypto_capabilities.config_count; c++) {
		if ((hba->crypto_cfg_array[c].config_enable & UFS_CRYPTO_CONFIGURATION_ENABLE) &&
			memcmp(&cfg.crypto_key, &hba->crypto_cfg_array[c].crypto_key,
				   UFS_CRYPTO_KEY_MAX_SIZE) == 0 &&
				   data_unit_mask == hba->crypto_cfg_array[c].data_unit_size &&
				   cap_idx ==  hba->crypto_cfg_array[c].crypto_cap_idx) {
			return c;
		}
 	}

	return -ENOKEY;
}

int ufshcd_crypto_erase_slot(void *hba_p, unsigned int slot) {
	struct ufs_hba *hba = hba_p;
	int c = 0;
	__le32 reg_base;
	union ufs_crypto_cfg_entry *cfg;
	if (!ufshcd_is_crypto_enabled(hba) ||
	    !crypto_cfg_slot_in_bounds(hba, slot)) {
		return -EINVAL;
	}

	cfg = &hba->crypto_cfg_array[slot];
	memset(cfg, 0, sizeof(union ufs_crypto_cfg_entry));
	reg_base = hba->crypto_cfg_register + slot * sizeof(union ufs_crypto_cfg_entry);

	/* Clear the crypto cfg on the device */
	for (c = 0; c < sizeof(union ufs_crypto_cfg_entry); c += sizeof(__le32)) {
		ufshcd_writel(hba, 0, reg_base + c);
	}

	return 0;
}

int ufshcd_crypto_find_cap(void* hba_p, size_t key_size_bytes,
			   enum keyslot_manager_algs alg, unsigned int data_unit_size) {
	struct ufs_hba *hba = hba_p;
	enum ufs_crypto_alg ufs_alg;
	u8 data_unit_mask;
	int c;
	enum ufs_crypto_key_size ufs_key_size;

	if (!ufshcd_hba_is_crypto_supported(hba)) {
		return -EINVAL;
	}

	switch (alg) {
		case AES_XTS: ufs_alg = UFS_CRYPTO_ALG_AES_XTS; break;
		case BITLOCKER_AES_CBC: ufs_alg = UFS_CRYPTO_ALG_BITLOCKER_AES_CBC;
					break;
		case AES_ECB: ufs_alg = UFS_CRYPTO_ALG_AES_ECB; break;
		case ESSIV_AES_CBC: ufs_alg = UFS_CRYPTO_ALG_ESSIV_AES_CBC; break;
		default: return -EINVAL;
	}

	/* AES_XTS needs two keys */
	if (ufs_alg == UFS_CRYPTO_ALG_AES_XTS) {
		key_size_bytes /= 2;
	} else if (key_size_bytes == 24) {
		/* All other encryption modes don't support 24 byte keys */
		return -EINVAL;
	}

	switch (key_size_bytes) {
		case 16: ufs_key_size = UFS_CRYPTO_KEY_SIZE_128; break;
		case 24: ufs_key_size = UFS_CRYPTO_KEY_SIZE_192; break;
		case 32: ufs_key_size = UFS_CRYPTO_KEY_SIZE_256; break;
		case 64: ufs_key_size = UFS_CRYPTO_KEY_SIZE_512; break;
		default: return -EINVAL;
	}

	if (get_ufs_data_mask_for_data_unit_size(data_unit_size,
						 &data_unit_mask) != 0) {
		return -EINVAL;
	}

	for (c = 0; c < hba->crypto_capabilities.num_crypto_cap; c++) {
		if (hba->crypto_cap_array[c].algorithm_id == ufs_alg &&
			(hba->crypto_cap_array[c].sdus_mask & data_unit_mask) != 0 &&
			hba->crypto_cap_array[c].key_size == ufs_key_size) {
			return c;
		}
	}

	return -EINVAL;
}

/**
 * ufshcd_crypto_set_enable_slot - enables/disables a crypto config slot
 * @hba:
 * @slot: The slot to modify
 * @enable: Whether to enable or disable the slot
 *
 * Returns 0 on success, negative number on failure.
 */
int ufshcd_crypto_set_enable_slot(struct ufs_hba *hba, unsigned int slot, bool enable) {
	__le32 offset, orig_value, new_value;
	if (!ufshcd_hba_is_crypto_supported(hba) ||
	    !crypto_cfg_slot_in_bounds(hba, slot)) {
		return -EINVAL;
	}

	offset = hba->crypto_cfg_register +
		 slot * sizeof(union ufs_crypto_cfg_entry) +
		 offsetof(union ufs_crypto_cfg_entry, config_enable);

	orig_value = ufshcd_readl(hba, offset);
	if (enable) {
		new_value = orig_value | UFS_CRYPTO_CONFIGURATION_ENABLE;
	}
	else {
		new_value = orig_value & (~UFS_CRYPTO_CONFIGURATION_ENABLE);
	}

	ufshcd_writel(hba, new_value, offset);

	return 0;
}

int ufshcd_crypto_enable(struct ufs_hba *hba, bool enable) {
	if (!ufshcd_hba_is_crypto_supported(hba)) {
		return -EINVAL;
	}

	if (enable) {
		hba->caps |= UFSHCD_CAP_CRYPTO;
		/* Write CRYPTO GENERAL ENABLE to the appropriate value */
		ufshcd_writel(hba,
			      CRYPTO_GENERAL_ENABLE |
			      (ufshcd_readl(hba, REG_CONTROLLER_ENABLE)),
			      REG_CONTROLLER_ENABLE);
	} else {
		hba->caps &= ~UFSHCD_CAP_CRYPTO;
		/* Write CRYPTO GENERAL ENABLE to the appropriate value */
		ufshcd_writel(hba,
			      (~CRYPTO_GENERAL_ENABLE) &
			      (ufshcd_readl(hba, REG_CONTROLLER_ENABLE)),
			      REG_CONTROLLER_ENABLE);
	}

	return 0;
}

void ufshcd_crypto_reset(struct ufs_hba *hba) {

}

/**
 * ufshcd_hba_init_crypto - Inits the crypto engine if it exists.
 * @hba: Per adapter instance
 *
 * Returns 0 on success. Returns -ENODEV if such capabilties don't exist, and
 * -ENOMEM upon OOM. In either error case, the UFS driver can and should
 * continue as if crypto capabiltites are not present.
 */
int ufshcd_hba_init_crypto(struct ufs_hba *hba) {
	int c = 0;
	int ret = 0;
	/* Default to disabling crypto */
	hba->caps &= ~UFSHCD_CAP_CRYPTO;

	if (!(hba->capabilities & MASK_CRYPTO_SUPPORT)) {
		ret = -ENODEV;
		goto out;
	}

	/**
	 * Crypto Capabilities should never be 0, because the
	 * config_array_ptr >= 04h. So we use a 0 value to indicate that
	 * crypto init failed, and can't be enabled.
	 */
	hba->crypto_capabilities.reg_val = ufshcd_readl(hba, REG_UFS_CCAP);
	hba->crypto_cfg_register = (u32)hba->crypto_capabilities.config_array_ptr *
							   (u32)0x100;
	hba->crypto_cap_array = devm_kcalloc(hba->dev,
					     hba->crypto_capabilities.num_crypto_cap,
					     sizeof(union ufs_crypto_cap_entry),
					     GFP_KERNEL);
	if (!hba->crypto_cap_array) {
		ret = -ENOMEM;
		goto out;
	}
	
	hba->crypto_cfg_array = devm_kcalloc(hba->dev,
					     (uint)hba->crypto_capabilities.config_count + 1,
					     sizeof(union ufs_crypto_cfg_entry),
					     GFP_KERNEL);
	if (!hba->crypto_cfg_array) {
		ret = -ENOMEM;
		goto out_cfg_mem;
	}
	
	/**
	 * Store all the capabilities now so that we don't need to repeatedly
	 * access the device each time we want to know its capabilities
	 */
	for (c = 0; c < hba->crypto_capabilities.num_crypto_cap; c++) {
		hba->crypto_cap_array[c].reg_val = ufshcd_readl(hba, REG_UFS_CRYPTOCAP +
														c * sizeof(__le32));
	}

	memset(hba->crypto_cfg_array, 0,
	       sizeof(union ufs_crypto_cfg_entry) *
	       ((uint)hba->crypto_capabilities.config_count + 1));

	return 0;
out_cfg_mem:
	devm_kfree(hba->dev, hba->crypto_cap_array);
out:
	// TODO: print error?
	/* Indicate that init failed by setting crypto_capabilities to 0 */
	hba->crypto_capabilities.reg_val = 0;
	return ret;
}

struct keyslot_mgmt_ll_ops ufshcd_ksm_ops = {
	.keyslot_program 	= ufshcd_crypto_program_key,
	.keyslot_release 	= ufshcd_crypto_erase_slot,
	.keyslot_find 		= ufshcd_crypto_find_slot_for_key,
	.crypto_alg_find 	= ufshcd_crypto_find_cap,
	.keyslot_evict		= ufshcd_crypto_erase_slot,
};
