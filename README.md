## SSH Probe

ssh-probe helps monitor and protect SSH sessions. Relying on predefined security profiles for each user, ssh-probe introduces a new access control layer that can restrict what a user can do on a server, including the root user. On a technical standpoint, ssh-probe relies on eBPF to collect runtime data on up to 127 hook points in the kernel. When an action diverges from the security profile of a session, ssh-probe relies on its syscall hook points to grant or deny access to specific operations. Access can also be granted through an MFA verification.

Monitoring and enforcement are organized in categories:

- File integrity monitoring
- Process monitoring
- Process level protections: includes protections against process injection techniques, ...
- Privilege elevation
- OS level protections: includes protections for the kernel and prevents the modification of sensitive parameters, ...
- Socket creation: this one essentially denies network access to the processes of the session
- Kill: this one isolates the kill syscalls so that you can grant access to them for a short period of time
- Performance monitoring: this one isolates the syscalls required for performance monitoring so that you can grant access to them for a short period of time

For each category (and each file for FIM and process monitoring), 4 options are available to define how ssh-probe shoud react:

- `allow`: ssh-probe will let the operation go through
- `block`: ssh-probe will block the operation, no matter what Linux's "normal" access control decided. This essentially means that it will block a standard user as well as a privileged user
- `mfa`: an MFA verification for the requested category (called `scope`) is required for ssh-probe to grant access to the operation
- `kill`: ssh-probe will block access to the operation and kill the SSH session that is responsible for trying to execute it

You can find a profile example in [profiles/vagrant.yaml](profiles/vagrant.yaml).

### Getting started

ssh-probe required on 3 binaries to work:

- `ssh-probe` is the main executable of the project, it is responsible for loading eBPF programs and maps into the kernel, loading profiles in the kernel and collecting security alerts (and forwarding them to the Datadog agent if you configured it).
- `ssh-probe-auth` is used for MFA verification. If you configured your profiles to use MFA, you should make sure that this binary is allowed in your profile.
- `ssh-probe-register` is used to generate new MFA secrets so that you can register a new app to work with `ssh-probe`. The ouptput of the binary is a QR code that you can scan with your MFA app, and a secret token for the newly registered user, that you need to share with `ssh-probe` using the `SSH_PROBE_SECRETS` environment variable.

#### System requirements
#### Build

### ssh-probe-register
### ssh-probe
### ssh-probe-auth
