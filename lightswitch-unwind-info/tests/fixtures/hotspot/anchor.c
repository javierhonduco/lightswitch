#define _GNU_SOURCE
#include <inttypes.h>
#include <jni.h>
#include <link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int armed;

static int libjvm_bias(struct dl_phdr_info *info, size_t size, void *data) {
  const char *name = strrchr(info->dlpi_name, '/');
  if (name && strcmp(name, "/libjvm.so") == 0) {
    *(uintptr_t *)data = info->dlpi_addr;
    return 1;
  }
  return 0;
}

JNIEXPORT void JNICALL Java_HotspotStack_arm(JNIEnv *env, jclass cls) {
  armed = 1;
}

JNIEXPORT jlong JNICALL Java_HotspotStack_probe(JNIEnv *env, jclass cls,
                                                jlong value) {
  if (armed) {
    uintptr_t bias;
    if (!dl_iterate_phdr(libjvm_bias, &bias))
      abort();
    // HotSpot's JNI wrapper has an ABI frame record even with Java
    // frame pointers disabled. Bootstrap only this first step from it.
    const uintptr_t *wrapper = __builtin_frame_address(1);
    printf("SNAPSHOT %" PRIxPTR " %" PRIxPTR " %" PRIxPTR "\n", bias,
           (uintptr_t)(wrapper + 2), wrapper[1]);
    fflush(stdout);
    raise(SIGSTOP);
  }
  return value;
}
