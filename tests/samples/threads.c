/*
 * Multi-threaded test program for LLDB MCP testing.
 * Compile with: gcc -g -pthread -o threads threads.c
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile int shared_counter = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* worker_thread(void* arg) {
    int id = *(int*)arg;
    printf("Thread %d started\n", id);

    for (int i = 0; i < 5; i++) {
        pthread_mutex_lock(&mutex);
        shared_counter++;
        int local_copy = shared_counter;
        pthread_mutex_unlock(&mutex);

        printf("Thread %d: counter = %d\n", id, local_copy);
        usleep(100000);  // 100ms
    }

    printf("Thread %d finished\n", id);
    return NULL;
}

void* sleeper_thread(void* arg) {
    int id = *(int*)arg;
    printf("Sleeper thread %d started\n", id);
    sleep(2);
    printf("Sleeper thread %d woke up\n", id);
    return NULL;
}

int main(int argc, char** argv) {
    printf("Multi-threaded test program started\n");

    pthread_t threads[3];
    int ids[] = {1, 2, 3};

    // Create worker threads
    for (int i = 0; i < 2; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &ids[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    // Create sleeper thread
    if (pthread_create(&threads[2], NULL, sleeper_thread, &ids[2]) != 0) {
        perror("pthread_create");
        return 1;
    }

    // Wait for all threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Final counter: %d\n", shared_counter);
    printf("Multi-threaded test program completed\n");

    return 0;
}
