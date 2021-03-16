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
	"time"

	"github.com/DataDog/ebpf/manager"
	"github.com/DataDog/gopsutil/host"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// ebpfManager holds the list of eBPF programs and maps of ssh-probe
var ebpfManager = &manager.Manager{
	Probes: []*manager.Probe{
		{Section: "uprobe/setlogin", BinaryPath: "/usr/sbin/sshd"},
		{Section: "tracepoint/sched/sched_process_fork"},
		{Section: "kprobe/__x64_sys_execve"},
		{Section: "kprobe/__x64_sys_execveat"},
		{Section: "kprobe/__x64_sys_unlinkat"},
		{Section: "kprobe/__x64_sys_unlink"},
		{Section: "kprobe/__x64_sys_rmdir"},
		{Section: "kprobe/__x64_sys_rename"},
		{Section: "kprobe/__x64_sys_renameat"},
		{Section: "kprobe/__x64_sys_renameat2"},
		{Section: "kprobe/__x64_sys_truncate"},
		{Section: "kprobe/__x64_sys_ftruncate"},
		{Section: "kprobe/__x64_sys_newfstatat"},
		{Section: "kprobe/__x64_sys_socket"},
		{Section: "kprobe/__x64_sys_socketpair"},
		{Section: "kprobe/__x64_sys_socketcall"},
		{Section: "kprobe/__x64_sys_setuid"},
		{Section: "kprobe/__x64_sys_setgid"},
		{Section: "kprobe/__x64_sys_setfsuid"},
		{Section: "kprobe/__x64_sys_setfsgid"},
		{Section: "kprobe/__x64_sys_setreuid"},
		{Section: "kprobe/__x64_sys_setregid"},
		{Section: "kprobe/__x64_sys_setresgid"},
		{Section: "kprobe/__x64_sys_setresuid"},
		{Section: "kprobe/__x64_sys_setpgid"},
		{Section: "kprobe/__x64_sys_setns"},
		{Section: "kprobe/__x64_sys_setsid"},
		//{Section: "kprobe/__x64_sys_setgroups"},
		{Section: "kprobe/__x64_sys_capset"},
		{Section: "kprobe/__x64_sys_personality"},
		{Section: "kprobe/__x64_sys_setpriority"},
		{Section: "kprobe/__x64_sys_sched_setparam"},
		{Section: "kprobe/__x64_sys_sched_setscheduler"},
		{Section: "kprobe/__x64_sys_sched_setaffinity"},
		{Section: "kprobe/__x64_sys_set_tid_address"},
		{Section: "kprobe/__x64_sys_set_thread_area"},
		{Section: "kprobe/__x64_sys_ioprio_set"},
		{Section: "kprobe/__x64_sys_acct"},
		{Section: "kprobe/__x64_sys_quotactl"},
		{Section: "kprobe/__x64_sys_ptrace"},
		{Section: "kprobe/__x64_sys_memfd_create"},
		{Section: "kprobe/__x64_sys_kcmp"},
		{Section: "kprobe/__x64_sys_process_vm_readv"},
		{Section: "kprobe/__x64_sys_process_vm_writev"},
		{Section: "kprobe/__x64_sys_userfaultfd"},
		{Section: "kprobe/__x64_sys_modify_ldt"},
		{Section: "kprobe/__x64_sys_kill"},
		{Section: "kprobe/__x64_sys_tkill"},
		{Section: "kprobe/__x64_sys_tgkill"},
		{Section: "kprobe/__x64_sys_create_module"},
		{Section: "kprobe/__x64_sys_delete_module"},
		{Section: "kprobe/__x64_sys_query_module"},
		{Section: "kprobe/__x64_sys_init_module"},
		{Section: "kprobe/__x64_sys_finit_module"},
		{Section: "kprobe/__x64_sys_reboot"},
		{Section: "kprobe/__x64_sys_settimeofday"},
		{Section: "kprobe/__x64_sys_clock_settime"},
		{Section: "kprobe/__x64_sys_clock_adjtime"},
		{Section: "kprobe/__x64_sys_stime"},
		{Section: "kprobe/__x64_sys_setrlimit"},
		//{Section: "kprobe/__x64_sys_sysinfo"},
		{Section: "kprobe/__x64_sys_syslog"},
		{Section: "kprobe/__x64_sys_getrusage"},
		{Section: "kprobe/__x64_sys_add_key"},
		{Section: "kprobe/__x64_sys_keyctl"},
		{Section: "kprobe/__x64_sys_request_key"},
		{Section: "kprobe/__x64_sys_unshare"},
		{Section: "kprobe/__x64_sys_get_kernel_syms"},
		{Section: "kprobe/__x64_sys_get_mempolicy"},
		{Section: "kprobe/__x64_sys_set_mempolicy"},
		{Section: "kprobe/__x64_sys_mbind"},
		{Section: "kprobe/__x64_sys_move_pages"},
		{Section: "kprobe/__x64_sys_migrate_pages"},
		{Section: "kprobe/__x64_sys_kexec_load"},
		{Section: "kprobe/__x64_sys_kexec_file_load"},
		{Section: "kprobe/__x64_sys_lookup_dcookie"},
		{Section: "kprobe/__x64_sys_mount"},
		{Section: "kprobe/__x64_sys_umount"},
		{Section: "kprobe/__x64_sys_umount2"},
		{Section: "kprobe/__x64_sys_name_to_handle_at"},
		{Section: "kprobe/__x64_sys_open_by_handle_at"},
		{Section: "kprobe/__x64_sys_nfsservctl"},
		{Section: "kprobe/__x64_sys_pivot_root"},
		{Section: "kprobe/__x64_sys_swapon"},
		{Section: "kprobe/__x64_sys_swapoff"},
		{Section: "kprobe/__x64_sys_sysfs"},
		{Section: "kprobe/__x64_sys__sysctl"},
		{Section: "kprobe/__x64_sys_uselib"},
		{Section: "kprobe/__x64_sys_ustat"},
		{Section: "kprobe/__x64_sys_chroot"},
		{Section: "kprobe/__x64_sys_sethostname"},
		{Section: "kprobe/__x64_sys_setdomainname"},
		{Section: "kprobe/__x64_sys_iopl"},
		{Section: "kprobe/__x64_sys_ioperm"},
		{Section: "kprobe/__x64_sys_open"},
		{Section: "kprobe/__x64_sys_openat"},
		{Section: "kprobe/vfs_open"},
		{Section: "kretprobe/__x64_sys_open", KProbeMaxActive: 512},
		{Section: "kretprobe/__x64_sys_openat", KProbeMaxActive: 512},
		{Section: "kprobe/__x64_sys_read"},
		{Section: "kprobe/__x64_sys_readv"},
		{Section: "kprobe/__x64_sys_preadv"},
		{Section: "kprobe/__x64_sys_preadv2"},
		{Section: "kprobe/__x64_sys_pread64"},
		{Section: "kprobe/__x64_sys_readdir"},
		{Section: "kprobe/__x64_sys_readahead"},
		{Section: "kprobe/__x64_sys_write"},
		{Section: "kprobe/__x64_sys_writev"},
		{Section: "kprobe/__x64_sys_pwritev"},
		{Section: "kprobe/__x64_sys_pwritev2"},
		{Section: "kprobe/__x64_sys_pwrite64"},
		{Section: "kprobe/__x64_sys_mmap"},
		{Section: "kprobe/__x64_sys_pipe"},
		{Section: "kprobe/__x64_sys_dup"},
		{Section: "kprobe/__x64_sys_dup2"},
		{Section: "kprobe/__x64_sys_dup3"},
		{Section: "kprobe/__x64_sys_sendfile"},
		{Section: "kprobe/__x64_sys_sendfile64"},
		{Section: "kprobe/__x64_sys_fcntl"},
		{Section: "kprobe/__x64_sys_flock"},
		{Section: "kprobe/__x64_sys_fsync"},
		{Section: "kprobe/__x64_sys_fdatasync"},
		{Section: "kprobe/__x64_sys_syncfs"},
		{Section: "kprobe/__x64_sys_sync_file_range"},
		{Section: "kprobe/__x64_sys_sync_fallocate"},
		{Section: "kprobe/__x64_sys_splice"},
		{Section: "kprobe/__x64_sys_tee"},
		{Section: "kprobe/__x64_sys_vmsplice"},
		{Section: "kprobe/__x64_sys_bpf"},
		{Section: "kprobe/__x64_sys_perf_event_open"},
	},
}

// NewSSHProbe parses the provided profiles and creates a new ssh-probe instance
func NewSSHProbe(profiles string, accessControlEventsLevel model.Action, disableGlobalScope bool, agentURL string) (*SSHProbe, error) {
	sshprobe := &SSHProbe{
		manager:                  ebpfManager,
		accessControlEventsLevel: accessControlEventsLevel,
		inodeCache:               make(map[uint64]string),
		disableGlobalScope:       disableGlobalScope,
		agentURL:                 agentURL,
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
