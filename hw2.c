#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/capability.h>

asmlinkage long sys_set_ban(int ban_getpid, int ban_pipe, int ban_kill, int ban_sig) {
    char new_bans = 0;

    // 1. Validation Check (Highest Priority: -EINVAL)
    // Check if any argument is negative
    if (ban_getpid < 0 || ban_pipe < 0 || ban_kill < 0 || ban_sig < 0) {
        return -EINVAL;
    }

    // 2. Privilege Check (Priority: -EPERM)
    // capable(CAP_SYS_ADMIN) is the standard kernel way to check for root privileges.
    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    // 3. Normalization
    // Arguments greater than 1 are to be considered as 1
    ban_getpid = (ban_getpid >= 1) ? 1 : 0;
    ban_pipe   = (ban_pipe >= 1) ? 1 : 0;
    ban_kill   = (ban_kill >= 1) ? 1 : 0;
    ban_sig    = (ban_sig >= 1) ? 1 : 0;

    // 4. Bitmasking into the single char
    // Bit 0: getpid
    // Bit 1: pipe
    // Bit 2: kill
    // Bit 3: signal
    if (ban_getpid) new_bans |= 1;        // Set bit 0 (00000001)
    if (ban_pipe)   new_bans |= (1 << 1); // Set bit 1 (00000010)
    if (ban_kill)   new_bans |= (1 << 2); // Set bit 2 (00000100)
    if (ban_sig)    new_bans |= (1 << 3); // Set bit 3 (00001000)

    // 5. Apply the bans to the current process
    // The 'current' macro acts as a pointer to the currently running task_struct
    current->syscall_bans = new_bans;

    // On success, return 0
    return 0;
}

asmlinkage long sys_get_ban(char ban) {
    // 1. Validation Check (-EINVAL)
    // Check if the requested ban is one of the allowed characters
    if (ban != 'g' && ban != 'p' && ban != 'k' && ban != 's') {
        return -EINVAL;
    }

    // 2. Check the specific bit based on the requested ban
    // We use the bitwise AND operator (&) to isolate the specific bit.
    // If the result is non-zero, the bit is set (banned).
    switch (ban) {
        case 'g': // getpid is mapped to bit 0
            return (current->syscall_bans & 1) ? 1 : 0;
            
        case 'p': // pipe is mapped to bit 1
            return (current->syscall_bans & (1 << 1)) ? 1 : 0;
            
        case 'k': // kill is mapped to bit 2
            return (current->syscall_bans & (1 << 2)) ? 1 : 0;
            
        case 's': // signal is mapped to bit 3
            return (current->syscall_bans & (1 << 3)) ? 1 : 0;
            
        default:
            return -EINVAL; // Fallback, though the first check prevents reaching here
    }
}

asmlinkage long sys_check_ban(pid_t pid, char ban) {
    struct pid *pid_struct;
    struct task_struct *target_task;
    int target_banned = 0;
    int caller_banned = 0;
    int bit_mask = 0;

    // 1. Validation Check (Priority 1: -EINVAL)
    switch (ban) {
        case 'g': bit_mask = 1; break;        // Bit 0
        case 'p': bit_mask = (1 << 1); break; // Bit 1
        case 'k': bit_mask = (1 << 2); break; // Bit 2
        case 's': bit_mask = (1 << 3); break; // Bit 3
        default: return -EINVAL;              // Invalid ban character
    }

    // 2. Find target process (Priority 2: -ESRCH)
    // We use the RCU lock to safely read process data without it disappearing
    rcu_read_lock(); 
    
    pid_struct = find_vpid(pid);
    if (!pid_struct) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (!target_task) {
        rcu_read_unlock();
        return -ESRCH;
    }

    // Extract the target process's ban status while we still hold the lock
    target_banned = (target_task->syscall_bans & bit_mask) ? 1 : 0;
    
    rcu_read_unlock(); // We are done reading the target process safely

    // 3. Permission Check (Priority 3: -EPERM)
    // The calling process (current) must not be banned from using this syscall
    caller_banned = (current->syscall_bans & bit_mask) ? 1 : 0;
    if (caller_banned) {
        return -EPERM;
    }

    // 4. Return target ban status on success
    return target_banned;
}

asmlinkage long sys_flip_ban_branch(int height, char ban) {
    int bit_mask = 0;
    int count = 0;
    int i;
    struct task_struct *parent_task;

    // 1. Validation Checks (Priority 1: -EINVAL)
    // Non-positive height is invalid
    if (height <= 0) {
        return -EINVAL;
    }

    switch (ban) {
        case 'g': bit_mask = 1; break;        // Bit 0
        case 'p': bit_mask = (1 << 1); break; // Bit 1
        case 'k': bit_mask = (1 << 2); break; // Bit 2
        case 's': bit_mask = (1 << 3); break; // Bit 3
        default: return -EINVAL;              // Invalid ban character
    }

    // 2. Permission Check (Priority 2: -EPERM)
    // The calling process must not be banned from using the syscall 'ban'
    if (current->syscall_bans & bit_mask) {
        return -EPERM;
    }

    // 3. Traverse the family tree
    // We start from the direct parent of the calling process
    parent_task = current->real_parent;
    
    for (i = 0; i < height; i++) {
        // Safety check: Don't go beyond the idle task (PID 0)
        if (parent_task->pid == 0) {
            break;
        }

        // Check if the parent is currently banned
        if (parent_task->syscall_bans & bit_mask) {
            // Ban exists -> lift the ban
            // We use bitwise AND with the NOT of the mask to clear only this specific bit
            parent_task->syscall_bans &= ~bit_mask;
        } else {
            // Ban does not exist -> impose the ban
            // We use bitwise OR to set this specific bit
            parent_task->syscall_bans |= bit_mask;
            
            // Only count when a parent is BANNED as a result of the syscall
            count++;
        }

        // Move one level up the tree to the next parent
        parent_task = parent_task->real_parent;
    }

    // 4. Return the number of parents that were newly banned
    return count;
}

if (nr == 39 && (current->syscall_bans & 1)) {
			is_banned = 1; // getpid
		} else if (nr == 22 && (current->syscall_bans & (1 << 1))) {
			is_banned = 1; // pipe
		} else if (nr == 62 && (current->syscall_bans & (1 << 2))) {
			is_banned = 1; // kill
		} else if (nr == 13 && (current->syscall_bans & (1 << 3))) {
			is_banned = 1; // rt_sigaction (signal)
		}

		if (is_banned) {
			// התהליך חסום. נכתוב את השגיאה ישירות לרגיסטר התשובה ונדלג על הביצוע
			regs->ax = -EPERM;
		} else {
			// התהליך לא חסום, או שזו קריאת מערכת אחרת. נבצע כרגיל.
			regs->ax = sys_call_table[nr](
				regs->di, regs->si, regs->dx,
				regs->r10, regs->r8, regs->r9);
		}