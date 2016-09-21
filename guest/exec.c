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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <asm/vmx.h>

#include "common/exec_policy.h"
#include "common/vmcall.h"
#include "guest/shared_mem.h"


static struct exec_policy *get_policy(struct exec_policies *policies,
				      struct uuid *uuid)
{
	struct exec_policy *policy;
	unsigned int *offsets;
	unsigned int i;

	offsets = (unsigned int *)policies->data;
	for (i = 0; i < policies->n; i++) {
		policy = (struct exec_policy *)(policies->data + offsets[i]);
		if (memcmp(&policy->uuid, uuid, sizeof(policy->uuid)) == 0)
			return policy;
	}

	return NULL;
}

/* get path i from policy */
static inline char *get_path(struct exec_policy *policy, unsigned int i)
{
	unsigned int *offsets;

	offsets = (unsigned int *)policy->data;

	return (char *)(policy->data + offsets[i]);
}

static int check_path(const char *policy_path, const char *path)
{
	size_t len;

	len = strlen(policy_path);
	if (len >= 2 && strncmp(policy_path + len - 2, "/*", 2) == 0) {
		if (strncmp(policy_path, path, len - 1) == 0 &&
		    strchr(path + len - 1, '/') == NULL)
			return 1;
	} else if (len >= 3 && strncmp(policy_path + len - 3, "/**", 3) == 0) {
		if (strncmp(policy_path, path, len - 2) == 0)
			return 1;
	} else {
		if (strcmp(path, policy_path) == 0)
			return 1;
	}

	return 0;
}

/* heavily modified version of ap_getparents() */
static void getparents(char *path)
{
	char *p, *q;

	/* a) remove ./ path segments */
	p = q = path;
	while (*q != '\x00') {
		if (q[0] == '/' && q[1] == '.' && q[2] == '/')
			q += 2;
		else
			*p++ = *q++;
	}

	/* b) remove trailing . path, segment */
	if (p[-1] == '.' && p[-2] == '/')
		p--;
	*p = '\x00';

	/* c) remove all xx/../ segments */
	p = q = path;
	while (*q != '\x00') {
		if (q[0] == '/' && q[1] == '.' && q[2] == '.' && q[3] == '/') {
			if (p != path) {
				do {
					p--;
				} while (*p != '/');
			}
			q += 3;

		} else {
			*p++ = *q++;
		}
	}
	*p = '\x00';

	/* d) remove trailing xx/.. segment. */
	if (p[-1] == '.' && p[-2] == '.' && p[-3] == '/') {
		if (p == path + 3) {
			path[1] = '\x00';
		} else {
			p -= 3;
			do {
				p--;
			} while (*p != '/');
			p[1] = '\x00';
		}
	}
}

static void no2slash(char *path)
{
	char *d, *p;

	p = d = path;
	while (*p != '\x00') {
		*d++ = *p;
		if (*p == '/') {
			do {
				p++;
			} while (*p == '/');
		}
		else {
			p++;
		}
	}

	*d = '\x00';
}

static char *canonical_path(const char *path)
{
	char *cpath;

	cpath = kstrdup(path, GFP_KERNEL);
	if (cpath == NULL)
		return NULL;

	no2slash(cpath);
	getparents(cpath);

	return cpath;
}

/* check if path is allowed for policy id.
 *
 * called from guest.*/
static int guest_exec_allowed(struct exec_policies *policies,
			      struct uuid *uuid,
			      const char *path)
{
	struct exec_policy *policy;
	const char *policy_path;
	unsigned int i;
	char *cpath;
	int allowed;

	policy = get_policy(policies, uuid);
	if (policy == NULL)
		return 0;

	/* path should be absolute and canonical, anyway... */
	if (path[0] != '/')
		return 0;

	cpath = canonical_path(path);
	if (cpath == NULL)
		return 0;

	allowed = 0;
	for (i = 0; i < policy->n; i++) {
		policy_path = get_path(policy, i);
		if (check_path(policy_path, cpath)) {
			allowed = 1;
			break;
		}

	}

	kfree(cpath);
	return allowed;
}

/* called from guest.
 *
 * Yes, guest is responsible of execve check. It makes no difference to do this
 * check from hypervisor than from guest: a compromised guest kernel can bypass
 * this check easily (eg: by modifying stub_execve address in sys_call_table).
 *
 * Since it's way more complicated and dangerous to do this check from
 * hypervisor (because guest memory must be read), let guest check execve
 * arguments.
 *
 *
 * execve can't be hooked directly, because execlp(), execvp(), and execvpe()
 * may try to execve different paths before succeed. The capsule must not be
 * killed on non-existent path.
 *
 * In consequence, hook prepare_binprm() which is called after open_exec(). */
int guest_prepare_binprm(struct linux_binprm *bprm)
{
	/* static variable */
	static int guest_first_execve = 1;

	struct exec_policies *exec_policies;
	struct uuid uuid;
	char *buf, *path;
	int allowed, ret;
	size_t size;

	size = 4096;
	buf = kmalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	path = dentry_path_raw(bprm->file->f_path.dentry, buf, size);
	if (IS_ERR(path)) {
		kfree(buf);
		return -EINVAL;
	}

	/* Path is resolved by dentry_path_raw(), there's no issue with symlink.
	 * Execution of a script triggers 2 calls to this function:
	 * /path/to/script.sh and /bin/sh. */

	exec_policies = shared_mem->exec_policies;
	guest_get_self_policy_uuid(&uuid);

	/* Always allow execution of wrapper (capsule_init), which is the first
	 * execve. This trick avoids to put wrapper path in every policy
	 * configuration file. */
	if (guest_first_execve) {
		guest_first_execve = 0;
		allowed = 1;
	} else {
		allowed = guest_exec_allowed(exec_policies, &uuid, path);
	}

	printk(KERN_ERR "execve in capsule: %s (allowed=%d)\n", path, allowed);
	kfree(buf);

	if (!allowed) {
		ret = -EPERM;
		if (0)
			cpu_vmcs_vmcall(VMCALL_FORBIDDEN_EXECVE, 0);
	} else {
		ret = 0;
	}

	return ret;
}
