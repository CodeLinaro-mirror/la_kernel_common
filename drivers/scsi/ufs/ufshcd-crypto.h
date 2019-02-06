/*
 * Universal Flash Storage Host controller driver
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
 */

#ifndef _UFSHCD_CRYPTO_H
#define _UFSHCD_CRYPTO_H

#include <linux/keyslot-manager.h>

#include "ufshci.h"

struct ufs_hba;

bool ufshcd_hba_is_crypto_supported(struct ufs_hba *hba);

bool crypto_cfg_slot_in_bounds(struct ufs_hba *hba, unsigned int slot);

int ufshcd_crypto_cfg_entry_write_key(union ufs_crypto_cfg_entry *cfg, u8 *key,
                                      size_t ufs_key_size,
                                      enum ufs_crypto_alg crypto_alg);

int ufshcd_crypto_program_key(void *hba, u8* key, size_t key_size_bytes,
			      unsigned int data_unit_size_bytes, unsigned int cap_idx,
			      unsigned int slot);

int ufshcd_crypto_find_slot_for_key(void *hba, u8 *key, size_t key_size_bytes,
				    unsigned int data_unit_size_bytes, unsigned int cap_idx);

int ufshcd_crypto_erase_slot(void *hba, unsigned int slot);

int ufshcd_crypto_find_cap(void* hba, size_t key_size_bytes,
						   enum keyslot_manager_algs alg,
						   unsigned int data_unit_size_bytes);

int ufshcd_crypto_set_enable_slot(struct ufs_hba *hba, unsigned int slot, bool enable);

int ufshcd_crypto_enable(struct ufs_hba *hba, bool enable);

bool ufshcd_is_crypto_enabled(struct ufs_hba *hba);

void ufshcd_crypto_reset(struct ufs_hba *hba);

int ufshcd_hba_init_crypto(struct ufs_hba *hba);

extern struct keyslot_mgmt_ll_ops ufshcd_ksm_ops;

#endif /* End of Header */
