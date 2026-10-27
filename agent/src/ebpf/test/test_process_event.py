#!/usr/bin/env python3
"""Execute actual process-event bodies with compiler-poisoned automatic storage."""
import argparse
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import tempfile
import unittest

PARSER = argparse.ArgumentParser()
PARSER.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
ARGS, UNIT_ARGS = PARSER.parse_known_args()
ROOT = ARGS.root.resolve()

def declaration(text, name):
    found = re.search(r"^struct " + name + r"\s*\{.*?^};", text, re.M | re.S)
    if not found:
        raise AssertionError("missing actual declaration " + name)
    return found.group()

def function(text, name):
    found = re.search(r"^static [^\n]*\b" + name + r"\([^)]*\)\s*\{", text, re.M)
    if not found:
        raise AssertionError("missing actual function " + name)
    depth, end = 1, found.end()
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[found.start():end]

PREAMBLE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <linux/types.h>
@DECLS@
struct member_fields_offset {int unused;};
static struct member_fields_offset offsets;
static __u64 current_id;
static int ready,events,proc_deletes,go_deletes,assertions;
static __u32 last_proc;
static __u64 last_go;
static struct process_event_t captured;
static int proc_info_map,goroutines_map,socket_data;
#define NAME(x) x
#define BPF_F_CURRENT_CPU 0xffffffffULL
static struct member_fields_offset *retrieve_ready_kern_offset(void) {
    return ready ? &offsets : NULL;
}
static __u64 bpf_get_current_pid_tgid(void) {return current_id;}
static int bpf_map_delete_elem(void *map,const void *key) {
    if(map==&proc_info_map){proc_deletes++;memcpy(&last_proc,key,sizeof(last_proc));}
    else {assert(map==&goroutines_map);go_deletes++;memcpy(&last_go,key,sizeof(last_go));}
    return 0;
}
static int bpf_get_current_comm(void *dst,unsigned len) {
    assert(len==TASK_COMM_LEN);memset(dst,0,len);memcpy(dst,"owned-gate",10);return 0;
}
static int bpf_perf_event_output(void *ctx,void *map,__u64 flags,void *data,unsigned size) {
    (void)ctx;assert(map==&socket_data && flags==BPF_F_CURRENT_CPU);
    assert(size==sizeof(captured));memcpy(&captured,data,size);events++;return 0;
}
"""
MAIN = r"""
#define CHECK(x) do {assertions++;assert(x);}while(0)
static void reset(__u32 pid,__u32 tid) {
    ready=1;events=proc_deletes=go_deletes=0;last_proc=0;last_go=0;
    current_id=((__u64)pid<<32)|tid;memset(&captured,0xcc,sizeof(captured));
}
static void expected(__u32 type,__u32 pid,bool maybe) {
    CHECK(events==1);CHECK(captured.meta.event_type==type);CHECK(captured.pid==pid);
    CHECK(captured.maybe_thread==maybe);CHECK(!memcmp(captured.name,"owned-gate",10));
    for(unsigned i=10;i<sizeof(captured.name);i++)CHECK(captured.name[i]==0);
}
int main(void) {
    CHECK(sizeof(struct process_event_t)==24);
    reset(1234,1234);CHECK(do_process_exit(NULL)==0);
    expected(EVENT_TYPE_PROC_EXIT,1234,false);
    CHECK(proc_deletes==1 && last_proc==1234);
    CHECK(go_deletes==1 && last_go==current_id);
    reset(1234,1235);CHECK(do_process_exit(NULL)==0);
    CHECK(events==0 && proc_deletes==0 && go_deletes==1 && last_go==current_id);
    reset(1234,1234);CHECK(__process_exec(NULL)==0);
    expected(EVENT_TYPE_PROC_EXEC,1234,false);CHECK(proc_deletes==0 && go_deletes==0);
    reset(1234,1235);CHECK(__process_exec(NULL)==0);CHECK(events==0);
    for(int maybe=0;maybe<=1;maybe++) {
        reset(1234,1234);CHECK(kernel_clone_exit(true,maybe,4321,NULL)==0);
        expected(EVENT_TYPE_PROC_EXEC,4321,maybe);
        reset(1234,1234);CHECK(kernel_clone_exit(false,maybe,0,NULL)==0);
        expected(EVENT_TYPE_PROC_EXEC,1234,maybe);
    }
    reset(1234,1234);CHECK(kernel_clone_exit(false,true,-1,NULL)==0);CHECK(events==0);
    reset(1234,1234);CHECK(kernel_clone_exit(false,true,4321,NULL)==0);CHECK(events==0);
    reset(1234,1235);CHECK(kernel_clone_exit(true,true,4321,NULL)==0);CHECK(events==0);
    reset(1234,1234);ready=0;CHECK(do_process_exit(NULL)==0);
    CHECK(__process_exec(NULL)==0);CHECK(kernel_clone_exit(true,true,4321,NULL)==0);
    CHECK(events==0 && proc_deletes==0 && go_deletes==0);
    printf("process_event_assertions=%d\n",assertions);return 0;
}
"""

def compiler(directory):
    candidates = [shlex.split(os.environ.get("CC", "cc"))]
    clang = shutil.which("clang")
    if clang:
        candidates.append([clang])
    probe = directory / "probe.c"
    probe.write_text("int main(void) {return 0;}\n")
    errors = []
    for command in candidates:
        result = subprocess.run(command + ["-ftrivial-auto-var-init=pattern", "-x", "c",
            str(probe), "-o", str(directory / "probe")], capture_output=True, text=True)
        if result.returncode == 0:
            return command
        errors.append(result.stderr)
    raise AssertionError("a compiler supporting -ftrivial-auto-var-init=pattern is required; " +
                         "\n".join(errors))

def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

class ProcessEventTests(unittest.TestCase):
    def test_actual_exit_exec_clone_with_poisoned_automatic_storage(self):
        source = (ROOT / "kernel/uprobe_base.bpf.c").read_text()
        header = (ROOT / "kernel/include/socket_trace_common.h").read_text()
        common = (ROOT / "kernel/include/common.h").read_text()
        definitions = [re.search(r"^#define TASK_COMM_LEN\s+\d+", common, re.M).group(),
            re.search(r"enum\s*\{[^}]*EVENT_TYPE_PROC_EXEC[^}]*};", header, re.S).group(),
            declaration(header, "event_meta"), declaration(header, "process_event_t")]
        actual = "\n".join(function(source, name) for name in
                           ("do_process_exit", "kernel_clone_exit", "__process_exec"))
        with tempfile.TemporaryDirectory(prefix="process-event-") as tmp:
            directory = Path(tmp)
            command = compiler(directory)
            path = directory / "events.c"
            path.write_text(PREAMBLE.replace("@DECLS@", "\n".join(definitions)) + actual + MAIN)
            result = subprocess.run(command + ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-Wno-unused-parameter", "-ftrivial-auto-var-init=pattern", str(path),
                "-o", str(directory / "events")], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(directory / "events")], capture_output=True, text=True,
                                    timeout=10, preexec_fn=no_core)
            self.assertEqual(result.returncode, 0, result.stderr)
            print("compiler=" + " ".join(command))
            print(result.stdout, end="")

if __name__ == "__main__":
    unittest.main(argv=[__file__] + UNIT_ARGS, verbosity=2)
