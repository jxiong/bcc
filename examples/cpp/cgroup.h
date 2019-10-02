#pragma once

struct cgroup_stats {
  uint64_t cpu_time; /* running time */
  uint32_t io_wait; /* iowait count */
  uint32_t sched; /* sched out times */

  uint32_t nr_file_opened; /* number of file being opened */
  uint64_t file_read_bytes;
  uint64_t file_write_bytes;

  uint32_t nr_memcg_reclaimed;

  uint64_t network_send_bytes;
  uint64_t network_recv_bytes;
};
