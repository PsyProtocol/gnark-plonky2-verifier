/* Test-only GNU ld wrappers. Track only allocations returned by the Go exports;
 * do not infer a leak from RSS, Go heap size, or glibc's arena reservation. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *proof; char *vk; } Proof;
enum { SLOTS = 65536 };
static uintptr_t pointers[SLOTS];
static size_t sizes[SLOTS];
/* allocated bytes, freed bytes, live bytes, allocated blocks, freed blocks,
 * cumulative input bytes, calls. All counters are requested bytes, not usable size. */
static uint64_t counters[7];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
extern void __real_free(void *);

static size_t slot(void *p) { return (((uintptr_t)p >> 4) * 11400714819323198485ull) & (SLOTS-1); }
static void track(void *p, size_t size) {
    if (!p) return;
    pthread_mutex_lock(&lock);
    size_t i = slot(p), n = 0;
    while (pointers[i] > 1 && ++n < SLOTS) i = (i+1) & (SLOTS-1);
    if (n == SLOTS) abort();
    pointers[i] = (uintptr_t)p; sizes[i] = size;
    counters[0] += size; counters[2] += size; counters[3]++;
    pthread_mutex_unlock(&lock);
}
void __wrap_free(void *p) {
    if (p) {
        pthread_mutex_lock(&lock);
        size_t i = slot(p), n = 0;
        while (pointers[i] && ++n <= SLOTS) {
            if (pointers[i] == (uintptr_t)p) {
                counters[1] += sizes[i]; counters[2] -= sizes[i]; counters[4]++;
                pointers[i] = 1; break;
            }
            i = (i+1) & (SLOTS-1);
        }
        pthread_mutex_unlock(&lock);
    }
    __real_free(p);
}
void audit_snapshot(uint64_t *out) {
    pthread_mutex_lock(&lock); memcpy(out, counters, sizeof counters); pthread_mutex_unlock(&lock);
}
static void inputs(const char *a,const char *b,const char *c,const char *d) {
    const char *v[4] = {a,b,c,d};
    pthread_mutex_lock(&lock);
    for (int i=0;i<4;i++) if(v[i]) counters[5] += strlen(v[i])+1;
    counters[6]++;
    pthread_mutex_unlock(&lock);
}
static Proof *proof_result(Proof *p) {
    if (p) {
        track(p, sizeof *p);
        if (p->proof) track(p->proof, strlen(p->proof)+1);
        if (p->vk) track(p->vk, strlen(p->vk)+1);
    }
    return p;
}
static char *string_result(char *s) { if(s) track(s,strlen(s)+1); return s; }

#ifdef AUDIT_MOCK
static Proof *mock_generate(char *a,char *b,char *c,char *d) {
    (void)b;(void)c;(void)d;
    if (!strcmp(a,"null_container")) return NULL;
    Proof *p = malloc(sizeof *p);
    p->proof = !strcmp(a,"null_proof") ? NULL : strdup(!strcmp(a,"error") ? "error: test failure" : "proof");
    p->vk = !strcmp(a,"null_vk") ? NULL : strdup(!strcmp(a,"error") ? "" : "vk");
    return p;
}
#define __real_GenerateGroth16Proof mock_generate
#define __real_GenerateGroth16ProofFromJson mock_generate
static char *__real_VerifyGroth16Proof(char *a,char *b) { (void)b; return !strcmp(a,"null_string") ? NULL : strdup(!strcmp(a,"bad") ? "false" : "true"); }
static void __real_Initialize(char *a) { (void)a; }
static char *__real_ExportSolidityVerifier(char *a) { return strdup(!strcmp(a,"bad") ? "error: missing setup" : "contract Verifier {}"); }
#else
extern Proof *__real_GenerateGroth16Proof(char*,char*,char*,char*);
extern Proof *__real_GenerateGroth16ProofFromJson(char*,char*,char*,char*);
extern char *__real_VerifyGroth16Proof(char*,char*);
extern void __real_Initialize(char*);
extern char *__real_ExportSolidityVerifier(char*);
#endif

Proof *__wrap_GenerateGroth16Proof(char*a,char*b,char*c,char*d) {
    inputs(a,b,c,d); return proof_result(__real_GenerateGroth16Proof(a,b,c,d));
}
Proof *__wrap_GenerateGroth16ProofFromJson(char*a,char*b,char*c,char*d) {
    inputs(a,b,c,d); return proof_result(__real_GenerateGroth16ProofFromJson(a,b,c,d));
}
char *__wrap_VerifyGroth16Proof(char*a,char*b) {
    inputs(a,b,NULL,NULL); return string_result(__real_VerifyGroth16Proof(a,b));
}
void __wrap_Initialize(char*a) { inputs(a,NULL,NULL,NULL); __real_Initialize(a); }
char *__wrap_ExportSolidityVerifier(char*a) {
    inputs(a,NULL,NULL,NULL); return string_result(__real_ExportSolidityVerifier(a));
}
