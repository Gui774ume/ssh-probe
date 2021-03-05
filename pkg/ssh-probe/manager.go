/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ssh_probe

import (
	"github.com/DataDog/ebpf/manager"
	"github.com/DataDog/gopsutil/host"
	"github.com/Gui774ume/ssh-probe/pkg/model"
	"time"
)

// ebpfManager holds the list of eBPF programs and maps of ssh-probe
var ebpfManager = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{Section: "uprobe/setlogin", BinaryPath: "/usr/sbin/sshd"},
		&manager.Probe{Section: "tracepoint/sched/sched_process_fork"},
		&manager.Probe{Section: "kprobe/__x64_sys_execve"},
		&manager.Probe{Section: "kprobe/__x64_sys_execveat"},
		&manager.Probe{Section: "kprobe/__x64_sys_unlinkat"},
		&manager.Probe{Section: "kprobe/__x64_sys_unlink"},
		&manager.Probe{Section: "kprobe/__x64_sys_rmdir"},
		&manager.Probe{Section: "kprobe/__x64_sys_rename"},
		&manager.Probe{Section: "kprobe/__x64_sys_renameat"},
		&manager.Probe{Section: "kprobe/__x64_sys_renameat2"},
		&manager.Probe{Section: "kprobe/__x64_sys_truncate"},
		&manager.Probe{Section: "kprobe/__x64_sys_ftruncate"},
		&manager.Probe{Section: "kprobe/__x64_sys_newfstatat"},
		&manager.Probe{Section: "kprobe/__x64_sys_socket"},
		&manager.Probe{Section: "kprobe/__x64_sys_socketpair"},
		&manager.Probe{Section: "kprobe/__x64_sys_socketcall"},
		&manager.Probe{Section: "kprobe/__x64_sys_setuid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setgid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setfsuid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setfsgid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setreuid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setregid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setresgid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setresuid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setpgid"},
		&manager.Probe{Section: "kprobe/__x64_sys_setns"},
		&manager.Probe{Section: "kprobe/__x64_sys_setsid"},
		//&manager.Probe{Section: "kprobe/__x64_sys_setgroups"},
		&manager.Probe{Section: "kprobe/__x64_sys_capset"},
		&manager.Probe{Section: "kprobe/__x64_sys_personality"},
		&manager.Probe{Section: "kprobe/__x64_sys_setpriority"},
		&manager.Probe{Section: "kprobe/__x64_sys_sched_setparam"},
		&manager.Probe{Section: "kprobe/__x64_sys_sched_setscheduler"},
		&manager.Probe{Section: "kprobe/__x64_sys_sched_setaffinity"},
		&manager.Probe{Section: "kprobe/__x64_sys_set_tid_address"},
		&manager.Probe{Section: "kprobe/__x64_sys_set_thread_area"},
		&manager.Probe{Section: "kprobe/__x64_sys_ioprio_set"},
		&manager.Probe{Section: "kprobe/__x64_sys_acct"},
		&manager.Probe{Section: "kprobe/__x64_sys_quotactl"},
		&manager.Probe{Section: "kprobe/__x64_sys_ptrace"},
		&manager.Probe{Section: "kprobe/__x64_sys_memfd_create"},
		&manager.Probe{Section: "kprobe/__x64_sys_kcmp"},
		&manager.Probe{Section: "kprobe/__x64_sys_process_vm_readv"},
		&manager.Probe{Section: "kprobe/__x64_sys_process_vm_writev"},
		&manager.Probe{Section: "kprobe/__x64_sys_userfaultfd"},
		&manager.Probe{Section: "kprobe/__x64_sys_modify_ldt"},
		&manager.Probe{Section: "kprobe/__x64_sys_kill"},
		&manager.Probe{Section: "kprobe/__x64_sys_tkill"},
		&manager.Probe{Section: "kprobe/__x64_sys_tgkill"},
		&manager.Probe{Section: "kprobe/__x64_sys_create_module"},
		&manager.Probe{Section: "kprobe/__x64_sys_delete_module"},
		&manager.Probe{Section: "kprobe/__x64_sys_query_module"},
		&manager.Probe{Section: "kprobe/__x64_sys_init_module"},
		&manager.Probe{Section: "kprobe/__x64_sys_finit_module"},
		&manager.Probe{Section: "kprobe/__x64_sys_reboot"},
		&manager.Probe{Section: "kprobe/__x64_sys_settimeofday"},
		&manager.Probe{Section: "kprobe/__x64_sys_clock_settime"},
		&manager.Probe{Section: "kprobe/__x64_sys_clock_adjtime"},
		&manager.Probe{Section: "kprobe/__x64_sys_stime"},
		&manager.Probe{Section: "kprobe/__x64_sys_setrlimit"},
		//&manager.Probe{Section: "kprobe/__x64_sys_sysinfo"},
		&manager.Probe{Section: "kprobe/__x64_sys_syslog"},
		&manager.Probe{Section: "kprobe/__x64_sys_getrusage"},
		&manager.Probe{Section: "kprobe/__x64_sys_add_key"},
		&manager.Probe{Section: "kprobe/__x64_sys_keyctl"},
		&manager.Probe{Section: "kprobe/__x64_sys_request_key"},
		&manager.Probe{Section: "kprobe/__x64_sys_unshare"},
		&manager.Probe{Section: "kprobe/__x64_sys_get_kernel_syms"},
		&manager.Probe{Section: "kprobe/__x64_sys_get_mempolicy"},
		&manager.Probe{Section: "kprobe/__x64_sys_set_mempolicy"},
		&manager.Probe{Section: "kprobe/__x64_sys_mbind"},
		&manager.Probe{Section: "kprobe/__x64_sys_move_pages"},
		&manager.Probe{Section: "kprobe/__x64_sys_migrate_pages"},
		&manager.Probe{Section: "kprobe/__x64_sys_kexec_load"},
		&manager.Probe{Section: "kprobe/__x64_sys_kexec_file_load"},
		&manager.Probe{Section: "kprobe/__x64_sys_lookup_dcookie"},
		&manager.Probe{Section: "kprobe/__x64_sys_mount"},
		&manager.Probe{Section: "kprobe/__x64_sys_umount"},
		&manager.Probe{Section: "kprobe/__x64_sys_umount2"},
		&manager.Probe{Section: "kprobe/__x64_sys_name_to_handle_at"},
		&manager.Probe{Section: "kprobe/__x64_sys_open_by_handle_at"},
		&manager.Probe{Section: "kprobe/__x64_sys_nfsservctl"},
		&manager.Probe{Section: "kprobe/__x64_sys_pivot_root"},
		&manager.Probe{Section: "kprobe/__x64_sys_swapon"},
		&manager.Probe{Section: "kprobe/__x64_sys_swapoff"},
		&manager.Probe{Section: "kprobe/__x64_sys_sysfs"},
		&manager.Probe{Section: "kprobe/__x64_sys__sysctl"},
		&manager.Probe{Section: "kprobe/__x64_sys_uselib"},
		&manager.Probe{Section: "kprobe/__x64_sys_ustat"},
		&manager.Probe{Section: "kprobe/__x64_sys_chroot"},
		&manager.Probe{Section: "kprobe/__x64_sys_sethostname"},
		&manager.Probe{Section: "kprobe/__x64_sys_setdomainname"},
		&manager.Probe{Section: "kprobe/__x64_sys_iopl"},
		&manager.Probe{Section: "kprobe/__x64_sys_ioperm"},
		&manager.Probe{Section: "kprobe/__x64_sys_open"},
		&manager.Probe{Section: "kprobe/__x64_sys_openat"},
		&manager.Probe{Section: "kprobe/vfs_open"},
		&manager.Probe{Section: "kretprobe/__x64_sys_open", KProbeMaxActive: 512},
		&manager.Probe{Section: "kretprobe/__x64_sys_openat", KProbeMaxActive: 512},
		&manager.Probe{Section: "kprobe/__x64_sys_read"},
		&manager.Probe{Section: "kprobe/__x64_sys_readv"},
		&manager.Probe{Section: "kprobe/__x64_sys_preadv"},
		&manager.Probe{Section: "kprobe/__x64_sys_preadv2"},
		&manager.Probe{Section: "kprobe/__x64_sys_pread64"},
		&manager.Probe{Section: "kprobe/__x64_sys_readdir"},
		&manager.Probe{Section: "kprobe/__x64_sys_readahead"},
		&manager.Probe{Section: "kprobe/__x64_sys_write"},
		&manager.Probe{Section: "kprobe/__x64_sys_writev"},
		&manager.Probe{Section: "kprobe/__x64_sys_pwritev"},
		&manager.Probe{Section: "kprobe/__x64_sys_pwritev2"},
		&manager.Probe{Section: "kprobe/__x64_sys_pwrite64"},
		&manager.Probe{Section: "kprobe/__x64_sys_mmap"},
		&manager.Probe{Section: "kprobe/__x64_sys_pipe"},
		&manager.Probe{Section: "kprobe/__x64_sys_dup"},
		&manager.Probe{Section: "kprobe/__x64_sys_dup2"},
		&manager.Probe{Section: "kprobe/__x64_sys_dup3"},
		&manager.Probe{Section: "kprobe/__x64_sys_sendfile"},
		&manager.Probe{Section: "kprobe/__x64_sys_sendfile64"},
		&manager.Probe{Section: "kprobe/__x64_sys_fcntl"},
		&manager.Probe{Section: "kprobe/__x64_sys_flock"},
		&manager.Probe{Section: "kprobe/__x64_sys_fsync"},
		&manager.Probe{Section: "kprobe/__x64_sys_fdatasync"},
		&manager.Probe{Section: "kprobe/__x64_sys_syncfs"},
		&manager.Probe{Section: "kprobe/__x64_sys_sync_file_range"},
		&manager.Probe{Section: "kprobe/__x64_sys_sync_fallocate"},
		&manager.Probe{Section: "kprobe/__x64_sys_splice"},
		&manager.Probe{Section: "kprobe/__x64_sys_tee"},
		&manager.Probe{Section: "kprobe/__x64_sys_vmsplice"},
		&manager.Probe{Section: "kprobe/__x64_sys_bpf"},
		&manager.Probe{Section: "kprobe/__x64_sys_perf_event_open"},
	},
}

// NewSSHProbe parses the provided profiles and creates a new ssh-probe instance
func NewSSHProbe(profiles string, notificationLevel model.Action, disableGlobalScope bool, agentURL string) (*SSHProbe, error) {
	sshprobe := &SSHProbe{
		manager:            ebpfManager,
		notificationLevel:  notificationLevel,
		inodeCache:         make(map[uint64]string),
		disableGlobalScope: disableGlobalScope,
		agentURL:           agentURL,
	}
	// Get boot time
	bt, err := host.BootTime()
	if err != nil {
		return nil, err
	}
	sshprobe.bootTime = time.Unix(int64(bt), 0)

	// set perf ring buffer handlers
	sshprobe.manager.PerfMaps = []*manager.PerfMap{
		&manager.PerfMap{
			Map: manager.Map{
				Name: "otp_requests",
			},
			PerfMapOptions: manager.PerfMapOptions{
				DataHandler: sshprobe.HandleOTPRequests,
				LostHandler: sshprobe.LostHandler,
			},
		},
		&manager.PerfMap{
			Map: manager.Map{
				Name: "kill_requests",
			},
			PerfMapOptions: manager.PerfMapOptions{
				DataHandler: sshprobe.HandleKillRequests,
				LostHandler: sshprobe.LostHandler,
			},
		},
		&manager.PerfMap{
			Map: manager.Map{
				Name: "notifications",
			},
			PerfMapOptions: manager.PerfMapOptions{
				DataHandler: sshprobe.HandleNotifications,
				LostHandler: sshprobe.LostHandler,
			},
		},
	}

	// load profiles
	if err := sshprobe.loadProfiles(profiles); err != nil {
		return nil, err
	}
	return sshprobe, nil
}
