## `priv_exec`

Run a program with different Linux privileges.

`priv_exec` is simplified [`setpriv`](https://www.man7.org/linux/man-pages/man1/setpriv.1.html) + [`sudo`](https://man7.org/linux/man-pages/man8/sudo.8.html).

```
~$ priv_exec -h

Usage:
	priv_exec [options] -- <prog> [<args...>]

Authenticate with root user and execute the given program with elevated or dropped privileges.
Environment is cleared if we are running with SUID/SGID enabled or if UID/GID is switched.
Sessions are stored in /run/priv_exec/ directory.

Options:
	-u|--uid=<UID>          Process user ID
	-g|--gid=<GID>          Process group ID
	--groups=<GROUPS>       Process groups
	--caps=<CAPS>           Process capabilities

	--no-save-session       Do not save terminal session
	--no-prompt             Do not show password prompt

	-k|--keep-env[=ENV]     Keep environment
	-c|--clear-env          Clear environment


	GROUPS:
	    clear | <GID1>,<GID2>,...

	CAPS:
	    cap_<NAME1>,cap_<NAME2>,...
	    +all[,-cap_<NAME1>,cap_<NAME2>,...]
	    -all

	ENV:
	    <VAR1>,<VAR2>,...
```

# Build / Install

Note that some libraries like `musl` do not have `yescrypt` hashing algorithm so far which is used in `/etc/shadow` on Ubuntu 22.

```
~$ sudo apt install gcc libcap-dev libcrypt-dev
~$ cc priv_exec.c -o priv_exec -lcap -lcrypt
```

Put the executable on `$PATH` and set Linux capabilities or SUID bit.

```
~$ sudo setcap all+ep /usr/local/bin/priv_exec
```
