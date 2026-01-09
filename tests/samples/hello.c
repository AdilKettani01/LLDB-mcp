/*
 * Simple test program for LLDB MCP testing.
 * Compile with: gcc -g -o hello hello.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile int global_var = 42;
const char* test_string = "LLDB_MCP_TEST_STRING";

void helper_function(int x) {
    int local = x * 2;
    printf("Helper called with %d, local = %d\n", x, local);
    global_var = local;
}

int recursive_function(int n) {
    if (n <= 1) {
        return n;
    }
    return recursive_function(n - 1) + recursive_function(n - 2);
}

int compute(int a, int b) {
    int sum = a + b;
    int product = a * b;
    helper_function(sum);
    return product;
}

int main(int argc, char** argv) {
    printf("Test program started\n");
    printf("Test string at: %p\n", (void*)test_string);

    int x = 10;
    int y = 20;

    // Call some functions for stepping tests
    int result = compute(x, y);
    printf("Compute result: %d\n", result);

    // Recursive call for backtrace testing
    int fib = recursive_function(5);
    printf("Fibonacci(5) = %d\n", fib);

    // Memory pattern for search testing
    char buffer[64];
    memset(buffer, 'A', 32);
    memcpy(buffer + 32, "PATTERN_MARKER", 14);
    buffer[46] = '\0';
    printf("Buffer: %s\n", buffer);

    printf("Global var: %d\n", global_var);
    printf("Test program completed\n");

    return 0;
}
