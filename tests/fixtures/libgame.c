#include <stdio.h>
#include <pthread.h>
__thread int tls_counter;
const char *renderer_ext = "VK_KHR_swapchain";
int game_tick(void) { tls_counter++; return printf("tick %d\n", tls_counter); }
static void *worker(void *arg) { (void)arg; return NULL; }
int game_spawn(void) { pthread_t t; return pthread_create(&t, NULL, worker, NULL); }
