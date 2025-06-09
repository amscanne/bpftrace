# bpftrace Language Specification

## 1. Introduction

bpftrace is a tracing tool for Linux, built on eBPF. Within bpftrace, probe
definitions are written in a bpftrace-specific language, often refered to
simply as bpftrace, or occasionally as bpfscript.

This document specifies the formal syntax and semantics of the bpftrace
language. The purpose of such a specification is to provide a canonical
reference for the language, deferring details about specific probe types, map
types, built-in functions to documentation for the tool itself. The
implementation will occasionally not match this specification, which is
indicative of a bug; either the bug should be fixed or the specification
adjusted in some way to accept the behavior.

The goal of this specification is to have no undefined behavior. For the
purposes of the specification we define "program" to be the body of any probe
in the bpftrace tool, and do not discuss other elements that appear in a
bpftrace script, such as the configuration

### 1.1 Constraints

While bpftrace is not kernel-specific, eBPF as a technology was developed
primarily to extend the kernel. In practice, this means two things:

1. bpftrace inherits many constraints that are imposed on the kernel.
1. A primary audience for bpftrace is familiar with the C programming
   and memory model, which feels "natural" in a kernel context.

These two items will come up in the context of this specifcation.

## 2. Lexical Structure

### 2.1 Character Set

bpftrace programs are written using the ASCII character set. You may use
extended characters within bpftrace strings, but these will be interpreted and
managed within bpftrace as a sequence of ASCII characters. There is no support
for codepoints or mechanisms for evaluating the display width of a string. Some
of these are implementation restrictions which could be relaxed over time.

As examples of the above constraints, the following is not valid:

```
$☺ = "hello"; print($☺);
```

But the following is valid:

```
print("☺");
```

### 2.2 Comments

bpftrace supports both single-line and multi-line comments:

```
// Single line comment

/*
 * Multi-line comment
 */
```

Comments can be used inline within code:

```
print(/* inline comment block */ 1);
```

### 2.3 Identifiers

Identifiers must match the following regular expression: `[_a-zA-Z][_a-zA-Z0-9]*`

Unlike C, identifiers in bpftrace are effectively namespaced. Functions, macros
and builtins appear as a raw identifier, without any leading prefix. All
variables must be prefixed with `$` but otherwise follow the same identifier
rules. Similarly, maps must be prefixed with `@` and then follow the same
identifier rules.

### 2.4 Keywords

The following are reserved keywords in bpftrace:

```
if else while for unroll break continue return config let macro
```

### 2.5 Literals

#### 2.5.1 Integer Literals

Integer literals can be defined in the following formats:

- Decimal (base 10): `123`
- Octal (base 8): `0123` (prefixed with `0`)
- Hexadecimal (base 16): `0x123` or `0X123` (prefixed with `0x` or `0X`)
- Scientific notation (base 10): `1e3` (equivalent to `1000`)

To improve readability of large numbers, underscores can be used as separators: `1_000_123_000`

Integer suffixes as found in C (e.g., `UL`, `LL`) are parsed but not used as size specifiers.

#### 2.5.2 String Literals

String literals are enclosed in double quotes: `"Hello, world!"`

Strings support the following escape sequences:
- `\n`: Newline
- `\t`: Tab
- `\0nn`: Octal value nn
- `\xnn`: Hexadecimal value nn

#### 2.5.3 Character Literals

Character literals are not supported. ASCII codes must be used instead:

```
BEGIN {
  printf("Echo A: %c\n", 65);  // 65 is ASCII for 'A'
}
```

## 3. Program Structure

A bpftrace program consists of three main parts:

1. **Preamble**: Preprocessor directives and type definitions
2. **Config Block** (optional): Configuration settings
3. **Action Blocks**: One or more probe definitions with associated actions

```
// Preamble
#include <linux/path.h>
struct MyStruct { int x; }

// Config Block (optional)
config = {
    stack_mode = perf;
    max_map_keys = 2048;
}

// Action Blocks
BEGIN {
    printf("Tracing started\n");
}

kprobe:do_nanosleep {
    printf("%s is sleeping\n", comm);
}

END {
    printf("Tracing complete\n");
}
```

### 3.1 Preamble

The preamble contains preprocessor directives and type definitions:

```
#include <linux/path.h>
#define RED "\033[31m"

struct MyStruct {
  int x;
}
```

### 3.2 Config Block

The config block allows setting bpftrace configuration variables:

```
config = {
    stack_mode = perf;
    max_map_keys = 2048;
}
```

The config block must be placed at the top of the script before any action blocks (even `BEGIN`).

### 3.3 Action Blocks

Each action block consists of three parts:

```
probe[,probe] /predicate/ {
  action
}
```

- **Probes**: Specifies the event and event type to attach to
- **Predicate** (optional): A condition that must be met for the action to be executed
- **Action**: The code to execute when the probe fires and the predicate is true

Multiple probes can be associated with a single action by separating them with commas:

```
kprobe:tcp_reset,kprobe:tcp_v4_rcv {
  printf("Entered: %s\n", probe);
}
```

Wildcards are supported in probe specifications:

```
kprobe:tcp_* {
  printf("Entered: %s\n", probe);
}
```

## 4. Types

### 4.1 Fundamental Types

bpftrace provides the following fundamental types:

| Type    | Description                |
|---------|----------------------------|
| uint8   | Unsigned 8-bit integer     |
| int8    | Signed 8-bit integer       |
| uint16  | Unsigned 16-bit integer    |
| int16   | Signed 16-bit integer      |
| uint32  | Unsigned 32-bit integer    |
| int32   | Signed 32-bit integer      |
| uint64  | Unsigned 64-bit integer    |
| int64   | Signed 64-bit integer      |
| string  | String                     |
| buffer  | Binary data buffer         |

Integers are by default represented as 64-bit signed values, but can be cast to other integer types.

### 4.2 Derived Types

#### 4.2.1 Structs

C-like structs are supported:

```
struct MyStruct {
  int a;
  char b[10];
}
```

Fields are accessed with the `.` operator. Fields of a pointer to a struct can be accessed with the `->` operator:

```
$ptr = (struct MyStruct *)arg0;
$st = *$ptr;
print($st.a);
print($ptr->a);
```

#### 4.2.2 Arrays

One-dimensional arrays are supported:

```
struct MyStruct {
  int y[4];
}

kprobe:dummy {
  $s = (struct MyStruct *)arg0;
  print($s->y[0]);
}
```

#### 4.2.3 Tuples

bpftrace supports immutable N-tuples (n > 1):

```
$a = (1, 2);
$b = (3, 4, $a);
```

Individual fields can be accessed with the `.` operator (zero-indexed):

```
$a = (1, 2);
print($a.0);  // Prints 1
```

## 5. Variables

bpftrace supports two types of variables:

### 5.1 Scratch Variables

Scratch variables are kept on the BPF stack and their names always start with `$`:

```
$myvar = 42;
```

Scratch variables are scoped to their lexical block:

```
$a = 1;
if ($a == 1) {
  $b = "hello";
  $a = 2;
}
// $b is not accessible here
```

Scratch variables can be declared with `let`:

```
let $a = 1;
let $b;
```

### 5.2 Map Variables

Map variables use BPF maps and exist for the lifetime of the bpftrace program. Map names always start with `@`:

```
@mymap = 42;
@mymap[pid] = comm;
```

Maps can be declared in the global scope with specific types:

```
let @a = hash(100);
let @b = percpulruhash(20);
```

Available map types:
- `hash` (BPF_MAP_TYPE_HASH)
- `lruhash` (BPF_MAP_TYPE_LRU_HASH)
- `percpuhash` (BPF_MAP_TYPE_PERCPU_HASH)
- `percpulruhash` (BPF_MAP_TYPE_LRU_PERCPU_HASH)
- `percpuarray` (BPF_MAP_TYPE_PERCPU_ARRAY)

## 6. Operators

### 6.1 Arithmetic Operators

| Operator | Description           |
|----------|-----------------------|
| +        | Addition              |
| -        | Subtraction           |
| *        | Multiplication        |
| /        | Division              |
| %        | Modulo                |

### 6.2 Logical Operators

| Operator | Description           |
|----------|-----------------------|
| &&       | Logical AND           |
| \|\|     | Logical OR            |
| !        | Logical NOT           |

### 6.3 Bitwise Operators

| Operator | Description           |
|----------|-----------------------|
| &        | Bitwise AND           |
| \|       | Bitwise OR            |
| ^        | Bitwise XOR           |
| <<       | Left shift            |
| >>       | Right shift           |

### 6.4 Relational Operators

| Operator | Description                |
|----------|----------------------------|
| <        | Less than                  |
| <=       | Less than or equal to      |
| >        | Greater than               |
| >=       | Greater than or equal to   |
| ==       | Equal to                   |
| !=       | Not equal to               |

### 6.5 Assignment Operators

| Operator | Description                                      |
|----------|--------------------------------------------------|
| =        | Assignment                                       |
| +=       | Addition assignment                              |
| -=       | Subtraction assignment                           |
| *=       | Multiplication assignment                        |
| /=       | Division assignment                              |
| %=       | Modulo assignment                                |
| <<=      | Left shift assignment                            |
| >>=      | Right shift assignment                           |
| &=       | Bitwise AND assignment                           |
| \|=      | Bitwise OR assignment                            |
| ^=       | Bitwise XOR assignment                           |

### 6.6 Increment and Decrement Operators

| Operator | Description                                      |
|----------|--------------------------------------------------|
| ++       | Increment                                        |
| --       | Decrement                                        |

## 7. Control Flow

### 7.1 Conditionals

#### 7.1.1 If/Else Statements

```
if (condition) {
  // if block
} else if (condition) {
  // else if block
} else {
  // else block
}
```

#### 7.1.2 Ternary Operator

```
condition ? ifTrue : ifFalse
```

### 7.2 Loops

#### 7.2.1 While Loops

```
while (condition) {
  // loop body
}
```

Within a while-loop, `continue` and `break` statements can be used to control flow.

#### 7.2.2 For Loops

For loops can be used to iterate over elements in a map (requires Linux 5.13+):

```
for ($kv : @map) {
  // $kv.0 is the key, $kv.1 is the value
}
```

#### 7.2.3 Unroll

Loop unrolling is supported with the `unroll` statement:

```
unroll(n) {
  // block to be repeated n times
}
```

### 7.3 Return

The `return` keyword is used to exit the current probe:

```
kprobe:do_nanosleep {
  if (pid != 1234) {
    return;
  }
  printf("Process 1234 is sleeping\n");
}
```

## 8. Expressions

### 8.1 Block Expressions

A block can be used as an expression, as long as the last statement of the block is an expression with no trailing semi-colon:

```
let $a = {
  let $b = 1;
  $b
};
// $a is 1
```

This can be used anywhere an expression can be used.

### 8.2 Type Conversion

Explicit type conversion is performed using casting:

```
$y = (uint32)$z;
$py = (int16 *)$pz;
```

Integer casts to a higher rank are sign extended. Conversion to a lower rank is done by zeroing leading bits.

Casting between integers and integer arrays is also supported:

```
$a = (uint8[8])12345;
$x = (uint64)$a;
```

## 9. Macros

bpftrace supports macros for code reuse:

```
macro add_one($x) {
  $x + 1
}

BEGIN {
  $a = 5;
  $b = add_one($a);  // $b = 6
}
```

Macros can accept variable and map arguments and can call other macros:

```
macro add_one_to_each($a, @b) {
  $a += 1;
  @b += 1;
  $a + @b
}

macro add_two($x) {
  add_one(add_one($x))
}
```

## 10. Address Spaces

bpftrace distinguishes between kernel and user address spaces. Pointers in bpftrace are associated with an address space, which determines how memory is accessed when dereferencing the pointer.

## 11. Execution Model

bpftrace programs are compiled to eBPF bytecode and loaded into the Linux kernel. The execution model consists of:

1. Parsing and compilation of the bpftrace program
2. Loading the compiled eBPF programs into the kernel
3. Attaching the eBPF programs to the specified probe points
4. Execution of the eBPF programs when probe events occur
5. Communication between kernel and user space via BPF maps

### 11.1 Invocation Modes

bpftrace built-in functions operate in one of three modes:

1. **Synchronous**: The function is executed immediately in kernel space
2. **Asynchronous**: The function is executed later in user space
3. **Compile-time**: The function is evaluated during compilation

Asynchronous operations can lead to unexpected behavior as updates can happen before user space had time to process the event.

## 12. Limitations

bpftrace has several limitations imposed by the underlying eBPF technology:

1. Limited stack size (512 bytes)
2. No support for floating-point numbers
3. Limited loop support (loops must be bounded)
4. No recursive function calls
5. Limited program size
