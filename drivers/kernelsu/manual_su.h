#ifndef __KSU_MANUAL_SU_H
#define __KSU_MANUAL_SU_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/err.h> // For IS_ERR and PTR_ERR

#define KSU_SU_VERIFIED_BIT (1UL << 0)

struct su_request_arg {
    pid_t target_pid;
    const char __user *user_password;
};

static inline bool ksu_is_current_verified(void)
{
    // Reading is fine, no changes needed here.
    return ((unsigned long)(current->cred->security) & KSU_SU_VERIFIED_BIT) != 0;
}

static inline void ksu_mark_current_verified(void)
{
    // The correct way to modify credentials in the kernel
    struct cred *new;

    // 1. Prepare a new, writable copy of the current credentials.
    new = prepare_creds();
    if (!new) {
        pr_err("ksu: unable to prepare new creds\n");
        return;
    }

    // 2. Modify the security field in the new copy.
    new->security = (void *)((unsigned long)(new->security) | KSU_SU_VERIFIED_BIT);

    // 3. Safely commit the new credentials.
    commit_creds(new);
}

int ksu_manual_su_escalate(uid_t target_uid, pid_t target_pid,
                           const char __user *user_password);

bool is_pending_root(uid_t uid);
void remove_pending_root(uid_t uid);
void add_pending_root(uid_t uid);
bool is_current_verified(void);
extern bool current_verified;
#endif