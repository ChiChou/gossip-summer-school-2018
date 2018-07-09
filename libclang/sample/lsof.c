#include <mach-o/dyld.h>

#include <rpc/rpc.h>
#include <sys/proc.h>
#include <sys/types.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "libproc.h"
#include "net/route.h"
#include "netinet/tcp_fsm.h"
#include "rpc/pmap_prot.h"
#include "sys/kern_control.h"
#include "sys/proc_info.h"


#if __LP64__
#define LC_ENCRYPT_INFO LC_ENCRYPTION_INFO_64
#define macho_encryption_info_command encryption_info_command_64

#define LC_SEGMENT_COMMAND LC_SEGMENT_64
#define macho_segment_command segment_command_64
#define macho_section section_64

#else
#define LC_ENCRYPT_INFO LC_ENCRYPTION_INFO
#define macho_encryption_info_command encryption_info_command

#define LC_SEGMENT_COMMAND LC_SEGMENT
#define macho_segment_command segment_command
#define macho_section section
#endif


#define LOG(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define REQUIRES(cond, msg) if (!(cond)) { \
  LOG(msg); \
  exit(-1); \
}


void checkport(pid_t pid) {
  LOG();
  LOG("list network connections on pid: %d", pid);
  int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
  LOG("buf size: %d", buf_size);

  REQUIRES(buf_size != -1, "unable to get process fd");
  struct proc_fdinfo *info_array = (struct proc_fdinfo *)malloc(buf_size);
  REQUIRES(info_array, "out of memory? must be kidding me");
  proc_pidinfo(pid, PROC_PIDLISTFDS, 0, info_array, buf_size);
  int n_fd = buf_size / PROC_PIDLISTFD_SIZE;

  for (int i = 0; i < n_fd; i++) {
    switch (info_array[i].proc_fdtype) {
    case PROX_FDTYPE_VNODE:
    {
      struct vnode_fdinfowithpath vnodeInfo;
      int byte_used =
          proc_pidfdinfo(pid, info_array[i].proc_fd, PROC_PIDFDVNODEPATHINFO,
                         &vnodeInfo, PROC_PIDFDVNODEPATHINFO_SIZE);
      if (byte_used == PROC_PIDFDVNODEPATHINFO_SIZE) {
        const char *path = vnodeInfo.pvip.vip_path;
        LOG("open file: %s", path);
      }
      break;
    }

    case PROX_FDTYPE_SOCKET:
    {
      struct socket_fdinfo socket_info;
      int byte_used =
          proc_pidfdinfo(pid, info_array[i].proc_fd, PROC_PIDFDSOCKETINFO,
                         &socket_info, PROC_PIDFDSOCKETINFO_SIZE);
      if (byte_used != PROC_PIDFDSOCKETINFO_SIZE)
        continue;
      if (socket_info.psi.soi_family == AF_INET &&
          socket_info.psi.soi_kind == SOCKINFO_TCP) {
        int local_port = (int)ntohs(
            socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);

        int remote_port = (int)ntohs(
            socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

        if (remote_port == 0) {
          LOG("listening on %d", local_port);
        } else {
          LOG("connection: %d -> %d", local_port, remote_port);
        }
      }
    }
    }

  }
}

void checksec() {
  struct mach_header *mh = (struct mach_header *)_dyld_get_image_header(0);
  struct load_command *lc;

  if (!mh) {
    LOG("unable to read macho header");
    exit(-1);
  }

  LOG("checksec on %s", _dyld_get_image_name(0));

  if (mh->magic == MH_MAGIC_64) {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header_64));
  } else {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header));
  }

  if (mh->flags & MH_PIE) {
    LOG("[+] PIE");
  }

  if (mh->flags & MH_ALLOW_STACK_EXECUTION) {
    LOG("[+] ALLOW_STACK_EXECUTION");
  }

  if (mh->flags & MH_NO_HEAP_EXECUTION) {
    LOG("[+] NO_HEAP_EXECUTION");
  }

  for (int i = 0; i < mh->ncmds; i++) {
    switch (lc->cmd) {
    case LC_ENCRYPT_INFO: {
      struct encryption_info_command *eic =
          (struct encryption_info_command *)lc;
      if (eic->cryptid != 0) {
        LOG("[+] encrypted");
      }
      break;
    }

    case LC_SEGMENT_COMMAND: {
      const struct macho_segment_command *seg =
          (struct macho_segment_command *)lc;
      bool is_restricted = false;
      if (strcmp(seg->segname, "__RESTRICT") == 0) {
        const struct macho_section *const sections_start =
            (struct macho_section *)((char *)seg +
                                     sizeof(struct macho_segment_command));
        const struct macho_section *const sections_end =
            &sections_start[seg->nsects];
        for (const struct macho_section *sect = sections_start;
             sect < sections_end; ++sect) {
          if (strcmp(sect->sectname, "__restrict") == 0)
            is_restricted = true;
        }
      }
      if (is_restricted) {
        LOG("[+] restricted");
      } else {
        LOG("[+] segment: %s", seg->segname);
      }
      break;
    }
    }
    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }
}


int main(int argc, char *argv[])
{
  checksec();

  if (argc == 2) {
    pid_t pid = (pid_t)atoi(argv[1]);
    checkport(pid);
  }

  return 0;
}

// vim:ft=cpp