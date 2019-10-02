/* vim: set ts=2 sw=2 expandtab: */
/*
 * Sched an interactive command line tool to monitor cgroup activies.
 *
 * Basic example of BCC and kprobes.
 *
 * USAGE: Sched
 *
 * Copyright (c) Jinshan Xiong
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <algorithm>
#include <unistd.h>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "BPF.h"

#include "cgroup.h"

struct cgroup_entry {
  uint32_t    id;
  std::string path;
};

static std::vector<cgroup_entry> cgroups;

static int handle_command(ebpf::BPF& bpf, const std::vector<std::string>& opts)
{
  const std::string cmd = opts.at(0);

  if (cmd.compare("help") == 0 || cmd.compare("?") == 0) {
    std::cout << "subcommands: [ ls | add <path> | del <id> | help ]\n";
    return 0;
  } else if (cmd.compare("ls") == 0) {
    auto count = 0;

    for (auto &it : cgroups) {
      if (it.id) {
        count++;
        std::cout << "cgroup id: " << it.id << ", path: " << it.path << "\n";
      }
    }
    std::cout << "Available cgroup count: " << count << "\n";

    return 0;
  } else if (cmd.compare("add") == 0) {
    if (opts.size() != 2) {
      std::cerr << "need the path of cgroup\n";
      return EINVAL;
    }

    const auto path = opts.at(1);
    struct stat statbuf{};
    if (stat(path.c_str(), &statbuf) || !S_ISDIR(statbuf.st_mode))
      return ENOTDIR;

    auto it = std::find_if(cgroups.begin(), cgroups.end(),
                [](const cgroup_entry& entry) { return (entry.id == 0); });
    if (it == cgroups.end())
      return ENOSPC;

    auto cgroup_array = bpf.get_cgroup_array("cgroups");
    auto update_res = cgroup_array.update_value(it - cgroups.begin(), path);
    if (update_res.code() != 0) {
        std::cerr << update_res.msg() << std::endl;
        return errno;
    }

    it->id = statbuf.st_ino;
    it->path = std::move(path);

    return 0;
  } else if (cmd.compare("del") == 0) {
    if (opts.size() != 2) {
      std::cerr << "need cgroup id.\n";
      return EINVAL;
    }

    auto id = stoul(opts.at(1));
    auto it = std::find_if(cgroups.begin(), cgroups.end(),
                [id](const cgroup_entry& entry) { return (entry.id == id); });
    if (it == cgroups.end())
      return ENOSPC;

    auto cgroup_array = bpf.get_cgroup_array("cgroups");
    auto update_res = cgroup_array.remove_value(it - cgroups.begin());
    if (update_res.code() != 0) {
        std::cerr << update_res.msg() << std::endl;
        return errno;
    }

    it->id = 0;
    it->path = std::string();

    return 0;
  } else if (cmd.compare("dump") == 0) {
    std::cout << "dump stats for cgroups:\n";

    auto cgroup_info_handle = bpf.get_hash_table<uint32_t, struct cgroup_stats>("cgroups_info");
    auto cgroup_info = cgroup_info_handle.get_table_offline();

    for (auto& it : cgroup_info) {
        std::cout << "cgroup ID: " << it.first << "\n";
        std::cout << "\tCPU: " << it.second.cpu_time << " IO: " << it.second.io_wait << "\n";
        std::cout << "\tFile: open_count: " << it.second.nr_file_opened << "\n";

        (void) cgroup_info_handle.remove_value(it.first);
    }
    return 0;
  }

  return EINVAL;
}

int main(int argc, char **argv) {
  ebpf::BPF bpf;
  auto init_res = bpf.init("/home/jinshan.xiong/srcs/bcc/examples/cpp/cgroup.c");
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto cgroup_array = bpf.get_cgroup_array("cgroups");
  cgroups = std::vector<cgroup_entry>(cgroup_array.capacity());

  auto attach_res =
      bpf.attach_tracepoint("sched:sched_switch", "on_sched_switch");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  auto attach_open_res = bpf.attach_kprobe("vfs_open", "on_vfs_open");
  if (attach_open_res.code() != 0) {
    std::cerr << attach_open_res.msg() << std::endl;
    return 1;
  }

  while (1) {
    std::string input;

    std::cout << "> ";
    if (!std::getline(std::cin, input))
      break;

    std::vector<std::string> cmd;
    std::string opt;
    std::stringstream ss{input};

    while (std::getline(ss, opt, ' ')) {
      if (opt.find_first_not_of(' ') != std::string::npos)
        cmd.emplace_back(opt);
    }
    if (cmd.size() == 0)
      continue;

    auto rc = handle_command(bpf, cmd);
    if (rc)
      std::cerr << "Error: " << strerror(rc) << "\n";
  }

  auto detach_res = bpf.detach_tracepoint("sched:sched_switch");
  if (detach_res.code() != 0) {
    std::cerr << detach_res.msg() << std::endl;
    return 1;
  }

  return 0;
}
