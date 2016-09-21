/*
 * (c) Copyright 2016 G. Campana
 * (c) Copyright 2016 Quarkslab
 *
 * This file is part of Cappsule.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/gfp.h>

#include "common/exec_policy.h"
#include "common/log.h"


/* check if pointer is out of policies pages */
static inline int out_of_bound(struct exec_policies *policies, void *p)
{
	return ((char *)p >= (char *)policies + policies->size) ||
	       ((char *)p < (char *)policies);
}

/* check if policy is valid */
static int check_userland_policy(struct exec_policies *policies,
				struct exec_policy *policy)
{
	char *end, *max_path, *path;
	unsigned int i, *offsets;
	int null_found;

	if (out_of_bound(policies, (char *)policy + sizeof(*policy))) {
		hv_err("%s: policy out of bound", __func__);
		return -1;
	}

	offsets = (unsigned int *)policy->data;
	if (out_of_bound(policies, offsets + policy->n)) {
		hv_err("%s: policy offsets out of bound", __func__);
		return -1;
	}

	max_path = NULL;
	for (i = 0; i < policy->n; i++) {
		path = policy->data + offsets[i];
		if (out_of_bound(policies, path)) {
			hv_err("%s: path of policy out of bound",
				__func__);
			return -1;
		}
		if (path > max_path)
			max_path = path;
	}

	if (policy->n > 0) {
		null_found = 0;
		end = (char *)policies + policies->size;
		for (; max_path < end; max_path++) {
			if (*max_path == '\x00') {
				null_found = 1;
				break;
			}
		}

		if (!null_found) {
			hv_err("%s: paths aren't null terminated", __func__);
			return -1;
		}
	}

	return 0;
}

/* check if policies are valid */
static int check_userland_policies(struct exec_policies *policies)
{
	struct exec_policy *policy;
	unsigned int *offsets;
	unsigned int i;

	offsets = (unsigned int *)policies->data;
	if (out_of_bound(policies, offsets + policies->n)) {
		hv_err("%s: policies offsets out of bound", __func__);
		return -1;
	}

	for (i = 0; i < policies->n; i++) {
		policy = (struct exec_policy *)(policies->data + offsets[i]);
		if (check_userland_policy(policies, policy) != 0)
			return -1;
	}

	return 0;
}

void free_exec_policies(struct exec_policies *policies)
{
	unsigned int order;

	order = get_order(policies->size);
	free_pages((unsigned long)policies, order);
}

struct exec_policies *copy_exec_policies(char __user *buf, size_t size)
{
	struct exec_policies *policies;
	unsigned int order;
	unsigned long ret;

	/* add an additional page in case policies went to be modified */
	order = get_order(size + PAGE_SIZE);
	policies = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (policies == NULL)
		return ERR_PTR(-ENOMEM);

	ret = copy_from_user(policies, buf, size);
	policies->size = size + PAGE_SIZE;
	if (ret != 0) {
		free_exec_policies(policies);
		return ERR_PTR(-EFAULT);
	}

	if (check_userland_policies(policies) != 0) {
		free_exec_policies(policies);
		return ERR_PTR(-EINVAL);
	}

	return policies;
}
