//go:build darwin

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libproc.h>

#define PIDS_INCR           (sizeof(int) * 32)
#define LIST_PIDS_RETRY_CNT 10

static int list_pids(pid_t **pids, size_t *count) {
	int nb;
	size_t buf_size = 0;

	if (!pids || !count || *pids) return -EINVAL;

	if ((nb = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0)) <= 0) {
		return -errno;
	}

	while ((size_t)nb > buf_size) {
		buf_size += PIDS_INCR;
	}

	*pids = malloc(buf_size);
	if (!*pids) {
		return -ENOMEM;
	}

	int i;
	for (i = 0; i < LIST_PIDS_RETRY_CNT; i++) {
		if ((nb = proc_listpids(PROC_ALL_PIDS, 0, *pids, (int)buf_size)) <= 0) {
			free(*pids);
			*pids = NULL;
			return -errno;
		}

		if ((size_t)nb + sizeof(int) < buf_size) {
			*count = nb / sizeof(int);
			break;
		}

		buf_size += PIDS_INCR;
		pid_t *tmp = realloc(*pids, buf_size);
		if (!tmp) {
			free(*pids);
			*pids = NULL;
			return -ENOMEM;
		}
		*pids = tmp;
	}
	if (i == LIST_PIDS_RETRY_CNT) {
		free(*pids);
		*pids = NULL;
		return -EAGAIN;
	}

	return 0;
}

// find_process_path_by_port looks up the process owning the given TCP source port.
// Returns: 0 = success (path written to buf), 1 = not found, negative = -errno.
int find_process_path_by_port(uint16_t port, char *buf, size_t buflen) {
	pid_t *pids = NULL;
	size_t pid_count;
	int err = list_pids(&pids, &pid_count);
	if (err != 0) return err;

	for (size_t i = 0; i < pid_count; i++) {
		int pid = pids[i];
		if (pid <= 0) continue;

		struct proc_taskallinfo tai;
		int nb = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &tai, sizeof(tai));
		if (nb <= 0) {
			if (errno == EPERM || errno == ESRCH) continue;
			free(pids);
			return -errno;
		}
		if ((size_t)nb < sizeof(tai)) continue;
		if (tai.pbsd.pbi_nfiles == 0) continue;

		size_t fds_bufsize = sizeof(struct proc_fdinfo) * tai.pbsd.pbi_nfiles;
		struct proc_fdinfo *fds = malloc(fds_bufsize);
		if (!fds) {
			free(pids);
			return -ENOMEM;
		}

		nb = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, (int)fds_bufsize);
		if (nb <= 0) {
			int e = errno;
			free(fds);
			if (e == ESRCH || e == EPERM) continue;
			free(pids);
			return -e;
		}

		int nf = nb / sizeof(struct proc_fdinfo);
		for (int j = 0; j < nf; j++) {
			if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;

			struct socket_fdinfo si;
			nb = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
			if (nb <= 0) {
				if (errno == EBADF || errno == ENOTSUP || errno == ESRCH) continue;
				free(fds);
				free(pids);
				return -errno;
			}
			if ((size_t)nb < sizeof(si)) continue;

			if (si.psi.soi_kind != SOCKINFO_TCP) continue;

			uint16_t lport = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
			if (lport != port) continue;

			// Match found. Resolve the process path.
			int ret = proc_pidpath(pid, buf, (uint32_t)buflen);
			free(fds);
			free(pids);
			if (ret <= 0) return -errno;
			return 0;
		}
		free(fds);
	}

	free(pids);
	return 1; // not found
}
