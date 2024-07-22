#include <stdio.h>

void print_message() {
    // Print a message
    printf("Hello, Debugger!\n");



    // Bit manipulation operations
    
    int bitwise_and = 0 & 1;
    int bitwise_or = 0 | 1;
    int bitwise_xor = 0 ^ 1;
    int left_shift = 0 << 1;
    int right_shift = 0 >> 1;


    printf("Bit Manipulation Operations:\n"); 
    printf("Bitwise AND: %d\n", bitwise_and);
    printf("Bitwise OR: %d\n", bitwise_or);
    printf("Bitwise XOR: %d\n", bitwise_xor);
    printf("Left shift: %d\n", left_shift);
    printf("Right shift: %d\n", right_shift);

    // Arithmetic operations
    int a = 10, b = 5;
    int sum = a + b;
    int difference = a - b;
    int product = a * b;
    float quotient = (float)a / b; // Ensure float division for quotient

    printf("Arithmetic Operations:\n");
    printf("Sum: %d\n", sum);
    printf("Difference: %d\n", difference);
    printf("Product: %d\n", product);
    printf("Quotient: %.2f\n", quotient); // Print quotient with 2 decimal places

    // Logical operations
    int x = 10, y = 5, z = 5;
    printf("Logical Operations:\n");
    printf("x > y is %s\n", x > y ? "true" : "false");
    printf("x < y is %s\n", x < y ? "true" : "false");
    printf("y == z is %s\n", y == z ? "true" : "false");
    printf("x && y is %s\n", x && y ? "true" : "false");
    printf("x || y is %s\n", x || y ? "true" : "false");

    // Control flow operations
    printf("Control Flow Operations:\n");
    for (int i = 0; i < 3; i++) {
        printf("Loop iteration %d\n", i);
    }
    if (x > y) {
        printf("x is greater than y\n");
    } else {
        printf("x is not greater than y\n");
    }

    

    // Data movement operations
    printf("Data Movement Operations:\n");
    int temp;
    temp = a;
    a = b;
    b = temp;

    printf("After swapping, a: %d, b: %d\n", a, b);
}

int main() {
    print_message();
    return 0;
}


