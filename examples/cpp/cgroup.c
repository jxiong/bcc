#include <linux/sched.h>
#include <linux/path.h>
#include <linux/dcache.h>

#include "cgroup.h"

#define MAX_CGROUP_ENTRY  10

BPF_CGROUP_ARRAY(cgroups, MAX_CGROUP_ENTRY);

/* check if a task belongs to cgroup */
static bool check_cgroup() {
  int i;
  for (i = 0; i < MAX_CGROUP_ENTRY; i++) {
    if (cgroups.check_current_task(i) > 0)
      return true;
  }
  return false;
}

/* mapping from pid to last sched_in time. */
BPF_PERCPU_ARRAY(running, uint64_t, 1);

/* mapping from cgroup id to 'struct cputime' */
BPF_HASH(cgroups_info, uint32_t, struct cgroup_stats);

static struct cgroup_stats *cgroup_find()
{
  if (check_cgroup()) {
    uint32_t id = bpf_get_current_cgroup_id();
    struct cgroup_stats zero = { 0 };

    return cgroups_info.lookup_or_init(&id, &zero);
  }

  return NULL;
}

int on_sched_switch(struct tracepoint__sched__sched_switch *args) {
  pid_t prev_pid = args->prev_pid;
  pid_t next_pid = args->next_pid;
  long prev_state = args->prev_state;
  uint64_t now = bpf_ktime_get_ns();
  uint32_t zero = 0;

  /* handle the process that is being scheduled out */
  uint64_t *prev_ts = running.lookup(&zero);
  if (prev_ts) {
    long duration = now - *prev_ts;

    struct cgroup_stats *ptr = cgroup_find();
    if (ptr) { /* TODO: it's racy */
      ptr->cpu_time += duration;
      ptr->sched++;

      if (args->prev_state == TASK_UNINTERRUPTIBLE)
        ptr->io_wait++;
    }
  }

  /* add next process into running map anyway because it's impossible
   * to know if the next pid belongs to a cgroup we're interested.
   */
  running.update(&zero, &now);

  return 0;
}

/*
	field:int root;	offset:8;	size:4;	signed:1;
	field:int id;	offset:12;	size:4;	signed:1;
	field:int level;	offset:16;	size:4;	signed:1;
	field:__data_loc char[] path;	offset:20;	size:4;	signed:1;
 */
int on_cgroup_rmdir(struct tracepoint__cgroup__cgroup_rmdir *args) {
  return 0;
}

int on_vfs_open(struct pt_regs *ctx, struct path *path) {
  struct cgroup_stats *ptr = cgroup_find();

  if (ptr) 
    ptr->nr_file_opened++;

  return 0;
}

/*
	field:int order;	offset:8;	size:4;	signed:1;
	field:int may_writepage;	offset:12;	size:4;	signed:1;
	field:gfp_t gfp_flags;	offset:16;	size:4;	signed:0;
	field:int classzone_idx;	offset:20;	size:4;	signed:1;
 */
int on_memcg_reclaim(struct tracepoint__vmscan__mm_vmscan_memcg_reclaim_begin *args) {
  return 0;
}
