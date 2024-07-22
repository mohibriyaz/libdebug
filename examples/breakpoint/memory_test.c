//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void change_memory(char *address)
{
    if (address != NULL)
    {
        // Example implementation: change the memory content
        address[0] = 'X';
    }
}

void validate_setter(char *address)
{
    if (address != NULL)
    {
        printf("Good!\n");
    }
}

void leak_address(char* address)
{
    if (address != NULL)
    {
        printf("Address leaked: %p\n", (void *)address);
    }
}

int main()
{
    char *buffer = malloc(256);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed at buffer\n");
        return 1;
    }
    printf("Buffer allocated at: %p\n", (void *)buffer);

    for (int i = 0; i < 256; i++)
    {
        buffer[i] = (char)i;
    }

    // Change memory at the start of the buffer
    change_memory(buffer);

    // Debugging statement to print buffer contents
    printf("Buffer contents at 128: %s\n", buffer + 128);

    // Check if memory from buffer+128 matches the string "abcd1234"
    if (!strncmp(buffer + 128, "abcd1234", 8))
    {
        validate_setter(buffer + 128);
    }

    // Free the allocated buffer
    free(buffer);

    // Allocate a larger buffer
    buffer = malloc(2048);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed at large buffer\n");
        return 1;
    }
    printf("Large buffer allocated at: %p\n", (void *)buffer);

    // Allocate a small buffer to avoid memory consolidation
    char *useless = malloc(32);
    if (useless == NULL) {
        fprintf(stderr, "Memory allocation failed at useless buffer\n");
        free(buffer);
        return 1;
    }
    printf("Useless buffer allocated at: %p\n", (void *)useless);

    // Free the large buffer and leak its address
    free(buffer);
    leak_address(buffer);

    // Free the useless buffer
    free(useless);

    return 0;
}
