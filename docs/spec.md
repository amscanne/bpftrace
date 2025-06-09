# bpftrace Language Specification

## 1. Introduction

bpftrace is a tracing tool for Linux, built on eBPF. Within bpftrace, probe definitions are written in a bpftrace-specific language, often referred to simply as bpftrace, or occasionally as bpfscript.

This document specifies the formal syntax and semantics of the bpftrace language. The purpose of this specification is to provide a canonical reference for the language, enabling the development of syntax highlighters, language servers, and other tooling, while also ensuring that future language features evolve coherently. Details about specific probe types, map types, and built-in functions are deferred to the tool's documentation.

The goal of this specification is to have no undefined behavior. For the purposes of the specification, we define "program" to be the body of any probe in the bpftrace tool, and do not discuss other elements that appear in a bpftrace script beyond the language itself.

### 1.1 Constraints

While bpftrace is not kernel-specific, eBPF as a technology was developed primarily to extend the kernel. In practice, this means two things:

1. bpftrace inherits many constraints that are imposed on eBPF and the kernel environment.
2. A primary audience for bpftrace is familiar with the C programming language and memory model, which feels "natural" in a kernel context.

These two items will come up throughout this specification.

## 2. Notation

The syntax is specified using a variant of Extended Backus-Naur Form (EBNF):

```
Production  = production_name "=" [ Expression ] "." .
Expression  = Term { "|" Term } .
Term        = Factor { Factor } .
Factor      = production_name | token [ "…" token ] | Group | Option | Repetition .
Group       = "(" Expression ")" .
Option      = "[" Expression "]" .
Repetition  = "{" Expression "}" .
```

Productions are expressions constructed from terms and the following operators, in increasing precedence:

```
|   alternation
()  grouping
[]  option (0 or 1 times)
{}  repetition (0 to n times)
```

Lowercase production names are used to identify lexical (terminal) tokens. Non-terminals are in CamelCase.

## 3. Source Code Representation

### 3.1 Character Set

bpftrace programs are written using the ASCII character set. Extended characters may be used within bpftrace strings, but these will be interpreted and managed as a sequence of ASCII characters. There is no support for Unicode codepoints or mechanisms for evaluating the display width of a string.

Example of invalid code:

```
$☺ = "hello"; print($☺);  // Invalid: non-ASCII in identifier
```

Example of valid code:

```
print("☺");  // Valid: non-ASCII in string literal
```

### 3.2 Line Terminators

bpftrace recognizes the following line terminators:
- Line feed (U+000A)
- Carriage return (U+000D)
- Carriage return followed by line feed (U+000D U+000A)

## 4. Lexical Elements

### 4.1 Comments

bpftrace supports two forms of comments:

1. **Line comments** start with `//` and continue to the end of the line
2. **Block comments** start with `/*` and end with `*/`

Block comments do not nest. Comments do not occur within string literals.

```
// Line comment

/*
 * Block comment
 */

print(/* inline comment */ 1);  // Valid
```

### 4.2 Tokens

bpftrace breaks source text into tokens, which form the vocabulary of the language. There are four classes of tokens: identifiers, keywords, operators and punctuation, and literals.

White space, formed from spaces (U+0020), horizontal tabs (U+0009), carriage returns (U+000D), and newlines (U+000A), is ignored except as it separates tokens.

### 4.3 Identifiers

Identifiers name program entities such as variables, maps, macros, and subprograms.

An identifier is a sequence of one or more letters and digits. The first character must be a letter or underscore.

```ebnf
identifier = letter { letter | digit } .
letter     = "_" | "a" … "z" | "A" … "Z" .
digit      = "0" … "9" .
```

bpftrace uses prefixes to namespace identifiers:
- **Scratch variables** start with `$`: `$myvar`, `$x`
- **Maps** start with `@`: `@mymap`, `@count`
- **Functions, macros, and subprograms** use unprefixed identifiers: `myfunction`, `add_one`
- **Positional parameters** use `$` followed by a digit: `$1`, `$2`, ..., `$N`
  - These represent command-line arguments passed to the bpftrace program
  - `$#` is a special builtin that returns the number of positional arguments supplied
  - Positional parameters default to zero in numeric context and empty string in string context

### 4.4 Keywords

The following keywords are reserved and may not be used as identifiers:

```
break      config     continue   else       for
if         import     let        macro      offsetof
return     sizeof     unroll
```

Note: `while` is deprecated and may be removed in future versions.

### 4.5 Operators and Punctuation

The following character sequences represent operators and punctuation:

```
+    -    *    /    %    &    |    ^
<<   >>   ++   --   ==   !=   <    <=
>    >=   &&   ||   !    ~

=    +=   -=   *=   /=   %=   &=   |=
^=   <<=  >>=

(    )    [    ]    {    }    ,    .
;    :    ->   ?    _    **
```

### 4.6 Integer Literals

An integer literal is a sequence of digits representing an integer constant. An optional prefix sets a non-decimal base: `0` for octal, `0x` or `0X` for hexadecimal.

```ebnf
int_lit        = decimal_lit | octal_lit | hex_lit | scientific_lit .
decimal_lit    = digit { [ "_" ] digit } .
octal_lit      = "0" octal_digit { [ "_" ] octal_digit } .
hex_lit        = "0" ( "x" | "X" ) hex_digit { [ "_" ] hex_digit } .
scientific_lit = decimal_lit "e" decimal_lit .
octal_digit    = "0" … "7" .
hex_digit      = "0" … "9" | "a" … "f" | "A" … "F" .
```

Integer literals may include underscores `_` for readability:

```
1_000_000    // Decimal
0x_FF_FF     // Hexadecimal
1e6          // Scientific notation (1000000)
```

**Integer Type Inference**: Integer literals default to the smallest possible type that can represent the value. For example, `1` is a `uint8` and `-1` is an `int8`. However, integers, scratch variables, and map keys/values are automatically upcast when necessary.

**Integer Suffixes**: C-style integer suffixes (e.g., `UL`, `LL`) are parsed for compatibility with C headers but are not used as size specifiers. The expressions `123UL`, `123U`, and `123LL` all result in the same integer type with a value of `123`.

**Time Unit Suffixes**: Duration suffixes convert integer values to nanoseconds:

```
ns    // nanoseconds (identity: 1ns = 1)
us    // microseconds (1us = 1000)
ms    // milliseconds (1ms = 1000000)
s     // seconds (1s = 1000000000)
m     // minutes (1m = 60000000000)
h     // hours (1h = 3600000000000)
d     // days (1d = 86400000000000)
```

Example:

```
$duration = 1m;
print($duration);  // prints 60000000000
```

All time values in bpftrace are represented as nanoseconds internally. The time suffixes provide convenient shorthand for common durations.

### 4.7 Boolean Literals

Boolean literals represent boolean truth values:

```
true
false
```

### 4.8 String Literals

A string literal represents a string constant obtained from concatenating a sequence of characters. String literals are enclosed in double quotes.

```ebnf
string_lit = `"` { unicode_char | escape_seq } `"` .
```

String literals support escape sequences:

```
\n   newline
\t   horizontal tab
\r   carriage return
\"   double quote
\\   backslash
\0nn octal byte value (up to 3 digits)
\xnn hexadecimal byte value (2 digits)
```

Example:

```
"Hello, world!\n"
"Tab:\tSeparated\tValues"
"\x48\x65\x6c\x6c\x6f"  // "Hello" in hex
```

## 5. Types

A type determines a set of values together with operations and methods specific to those values.

### 5.1 Type Syntax

```ebnf
Type = IntType | SizedType | StructType | ArrayType | PointerType | TupleType | RecordType | TypeName .
```

### 5.2 Integer Types

Integer types represent sets of integer values.

```ebnf
IntType = "int8" | "int16" | "int32" | "int64" |
          "uint8" | "uint16" | "uint32" | "uint64" | "bool" .
```

| Type   | Description              | Size    |
|--------|--------------------------|---------|
| int8   | Signed 8-bit integer     | 1 byte  |
| int16  | Signed 16-bit integer    | 2 bytes |
| int32  | Signed 32-bit integer    | 4 bytes |
| int64  | Signed 64-bit integer    | 8 bytes |
| uint8  | Unsigned 8-bit integer   | 1 byte  |
| uint16 | Unsigned 16-bit integer  | 2 bytes |
| uint32 | Unsigned 32-bit integer  | 4 bytes |
| uint64 | Unsigned 64-bit integer  | 8 bytes |
| bool   | Boolean value            | 1 byte  |

Integer literals without an explicit type are represented using the smallest possible type. For example, `1` is a `uint8` and `-1` is an `int8`. However, integers are automatically upcast when necessary:

```
$a = 1;       // starts as uint8
$b = -1000;   // starts as int16
$a = $b;      // $a now becomes an int16

$c = (uint64)1;
$d = (int64)-1;
$c = $d;      // ERROR: type mismatch because there isn't a larger type that fits both
```

### 5.3 String and Buffer Types

```ebnf
SizedType = ( "string" | "buffer" ) "[" int_lit "]" .
```

Sized types must have an explicit size parameter:

- `string[N]`: Fixed-size string buffer of N bytes (NULL-terminated character array)
- `buffer[N]`: Fixed-size binary buffer of N bytes

bpftrace uses strings represented as well-formed character arrays (NULL-terminated), similar to C. All BTF character arrays (`char[]` or `int8[]`) are automatically converted to a bpftrace string. The maximum string length is controlled by the `max_strlen` configuration variable (default: 1024 bytes).

### 5.4 Struct Types

A struct is a sequence of named elements called fields, each of which has a name and a type.

```ebnf
StructType = ( "struct" | "union" | "enum" ) identifier "{" { FieldDecl } "}" .
FieldDecl  = Type identifier [ "[" int_lit "]" ] ";" .
```

Structs defined in the preamble are available throughout the program:

```
struct Point {
  int64 x;
  int64 y;
}
```

**Field Access**: Fields are accessed with the `.` operator for both struct values and pointers to structs. When the `.` operator is used on a pointer, it is automatically dereferenced:

```
$p.x          // Access field of struct value
$ptr.x        // Access field through pointer (automatic dereference)
```

The legacy `->` operator may be used but is purely an alias for the `.` operator.

**Struct Construction**: Constructing structs from scratch (like `struct X var = {.f1 = 1}` in C) is not supported. Structs can only be read into a variable from a pointer:

```
struct MyStruct {
  int a;
}

kprobe:dummy {
  $ptr = (struct MyStruct *) arg0;
  $st = *$ptr;      // Read struct from pointer
  print($st.a);     // Access field of struct value
  print($ptr.a);    // Access field through pointer (automatic dereference)
}
```

### 5.5 Array Types

An array is a numbered sequence of elements of a single type.

```ebnf
ArrayType = Type "[" int_lit "]" .
```

Arrays can appear as struct fields:

```
struct Data {
  int values[10];
}
```

Elements are accessed with the `[]` operator:

```
$data.values[0]
```

### 5.6 Pointer Types

A pointer type denotes the set of all pointers to variables of a given type, called the base type.

```ebnf
PointerType = "*" Type .
```

Examples:

```
int64 *      // Pointer to int64
struct Point *  // Pointer to Point struct
```

### 5.7 Tuple Types

A tuple is an immutable, ordered collection of values of potentially different types. Tuples are a sequence type where, unlike an array, every element can have a different type.

Tuples are constructed using parentheses with comma-separated values:

```
(1, 2)
(1, "hello", true)
($x, $y, $z)
(1, (2, 3), 4)     // Nested tuples
```

**Special Tuple Forms**: Single-element and empty tuples use Python-like syntax:
- Single-element tuple requires a trailing comma: `(1,)`
- Empty tuple: `()`

**Tuple Element Access**: Tuple elements are accessed with the `.` operator or array-style access using zero-based indexing. The array index expression must evaluate to an integer literal at compile time (no variables, but constant expressions like `[1-1]` are allowed):

```
$t = (1, "hello");
$first = $t.0;     // 1
$second = $t[1];   // "hello"
(1, "hello")[0]    // 1
```

**Examples**:

```
interval:s:1 {
  $a = (1,"hello");
  $b = (3,4, $a);
  print($a);     // (1, "hello")
  print($b);     // (3, 4, (1, "hello"))
  print($b.0);   // 3
  print($a[1]);  // "hello"
}
```

Tuples are immutable after creation. They can contain expressions of any type, including other tuples.

### 5.8 Record Types

A record is an immutable collection of named fields with values of potentially different types. Unlike tuples, records are not sensitive to field ordering and allow field access by name rather than by position.

```ebnf
RecordType = "(" RecordField { "," RecordField } ")" .
RecordField = identifier "=" Expression .
```

Records are constructed using parentheses with named field assignments:

```
(a=1, b=2)
(name="hello", count=42, active=true)
(x=$x, y=$y, z=$z)
```

Record fields are accessed with the `.` operator using field names:

```
$r = (x=1, y=2, z=3);
$x_val = $r.x;     // 1
$y_val = $r.y;     // 2
```

Records are immutable after creation. Field order is not significant - `(a=1, b=2)` is identical to `(b=2, a=1)`. Records can contain expressions of any type, including other records and tuples.

## 6. Properties of Types and Values

### 6.1 Type Identity

Two types are identical if they have the same structure and type names. Two named struct types are identical only if they have the same name.

### 6.2 Assignability

A value of type T is assignable to a variable of type U if:
- T and U are identical
- T and U are both integer types and T can be converted to U
- T is a tuple and U is a tuple with the same number of elements, and each element of T is assignable to the corresponding element of U
- T is a record and U is a record with the same field names (order-independent), and each field of T is assignable to the corresponding field of U

### 6.3 Representability

An integer constant is representable by a value of integer type if the constant can be represented by the range of the integer type.

### 6.4 Type Conversions

Explicit type conversions are performed using casts:

```
(uint32)$x       // Convert to uint32
(struct Point *)$ptr  // Cast to pointer type
```

**Integer Casts**: Casts to a higher rank are sign-extended. Conversion to a lower rank is done by zeroing leading bits.

**Pointer Casts**: Pointer types can be cast between different pointer types:

```
$py = (int16 *)$pz;
```

**Array Casts**: Casting between integers and integer arrays is supported. Both the source and destination type must have the same size:

```
$a = (uint8[8])12345;  // Convert integer to byte array
$x = (uint64)$a;       // Convert byte array to integer
```

When casting to an array, the size can be omitted and will be automatically determined from the source value's size:

```
$a = (uint8[])12345;   // Size inferred from integer size
```

Example showing byte array conversion:

```
begin {
  $a = (int8[8])12345;
  printf("%x %x\n", $a[0], $a[1]);  // Prints: 39 30
  printf("%d\n", (uint64)$a);        // Prints: 12345
}
```

Array casting is especially useful for working with IP addresses, where different parts of the kernel use different representations (byte arrays vs integers).

### 6.5 Memory Model

bpftrace programs execute within the constraints of the eBPF virtual machine, which imposes specific limitations on memory usage and organization. This section describes how values are stored and managed during program execution.

#### 6.5.1 Memory Locations

Values in bpftrace can reside in three primary locations:

1. **BPF Stack**: A limited 512-byte stack used for local variables and small intermediate values
2. **BPF Maps**: Persistent data structures that survive across probe invocations
3. **Global Arrays**: Pre-allocated per-CPU arrays used for values that exceed stack capacity

The exact location of scratch variables and intermediate values is implementation-defined. The compiler may automatically move values between these locations to satisfy eBPF constraints.

#### 6.5.2 Scratch Variable Storage

Scratch variables (identifiers starting with `$`) are typically stored on the BPF stack when their size permits. The BPF stack is limited to 512 bytes total across all active variables in a probe.

```
$x = 42;              // Stored on BPF stack (1 byte for uint8)
$name = "process";    // May be on stack or spilled, depending on size
```

When a scratch variable's size exceeds the `on_stack_limit` configuration (default: 32 bytes), the compiler automatically spills it to a pre-allocated global array instead of the stack. This automatic spilling is transparent to the program.

#### 6.5.3 Automatic Spilling to Global Arrays

Objects larger than `on_stack_limit` are stored in per-CPU global arrays to prevent stack exhaustion. These global arrays have a three-level nested structure:

```
global_array[CPU_ID][key][data]
```

- **First level**: Indexed by CPU ID (0 to MAX_CPU_ID) to avoid contention between CPUs
- **Second level**: Indexed by a key for each distinct spilled object within the program
- **Third level**: The actual data storage (byte array or value)

This structure ensures that concurrent probe invocations on different CPUs do not interfere with each other when accessing spilled variables.

**Example**: A large string that cannot fit on the stack:

```
$large_path = str(path);  // If path exceeds on_stack_limit, automatically spilled
                          // Stored at global_array[cpu_id][0][data]
```

#### 6.5.4 Storage Semantics by Type

The storage representation differs based on type:

- **Basic types** (int8, int16, int32, int64, uint8, uint16, uint32, uint64, bool): Stored by value
- **Structs and arrays**: Always stored by reference, even when dereferenced (see Section 8.2)
- **Tuples and records**: Stored by value if all elements are basic types; otherwise may contain references
- **Strings and buffers**: Stored by value if small enough for stack; otherwise spilled to global arrays

See Section 8.2 for detailed storage semantics of scratch variables.

#### 6.5.5 Map Storage

Maps (identifiers starting with `@`) are implemented as BPF maps and persist for the lifetime of the bpftrace program. Map storage is independent of the BPF stack and is not subject to the 512-byte limit.

```
@count = hash(1024);     // BPF map with 1024 max entries
@start[tid] = nsecs;     // Map value stored in BPF map, not on stack
```

Map access returns a pointer to the value, not the value itself. This pointer remains valid until the next map operation that could invalidate it.

#### 6.5.6 Stack Pressure and Best Practices

Programs that approach or exceed the 512-byte stack limit will fail to load. To manage stack pressure:

1. **Reduce data size**: Use smaller types where possible (e.g., `pid` instead of `comm`)
2. **Minimize map keys**: Fewer map keys reduce stack usage for key construction
3. **Split complex probes**: Divide work across multiple probe definitions
4. **Adjust on_stack_limit**: Lower the threshold to spill more aggressively (default: 32 bytes)

The compiler enforces a maximum allocation size of 256 bytes for individual stack allocations as a safety measure.

#### 6.5.7 Implementation-Defined Behavior

The following aspects of memory management are implementation-defined:

- Whether a value of a given size is stored on stack or spilled to global arrays
- The exact layout of spilled values in global arrays
- The order in which multiple spilled values are allocated keys
- Whether the compiler optimizes away unused allocations

Programs should not depend on specific memory locations or layout. The memory model guarantees only that values are correctly stored and retrieved, not where they reside.

## 7. Blocks

A block is a sequence of declarations and statements within matching brace brackets:

```ebnf
Block = "{" StatementList "}" .
StatementList = { Statement ";" } .
```

Blocks can be nested. Each block introduces a new lexical scope.

## 8. Declarations and Scope

### 8.1 Declarations

```ebnf
Declaration = VarDecl | MapDecl | SubprogDecl | MacroDecl .
```

### 8.2 Variable Declarations

**Scratch Variables**: Scratch variables are local to the current action block and exist only during the execution of that block. They start with `$`:

```ebnf
VarDecl = "let" "$" identifier [ "=" Expression ] .
```

Examples:

```
let $x;           // Declare without initialization
let $y = 42;      // Declare with initialization
$z = "hello";     // Implicit declaration by assignment
```

Scratch variables have automatic type inference on first assignment and cannot change type:

```
$a = 1;           // Type inferred as uint8
$a = 100;         // Valid: same type
$a = "string";    // ERROR: cannot change type from uint8 to string
```

**Storage Semantics**: Basic types (integers, booleans) are stored by value. **Structs and arrays are always stored by reference** in BPF, even when dereferenced. For example:

```
$ptr = (struct task_struct *)curtask;
$task = *$ptr;    // $task still stores a pointer internally, not the full struct value
$tuple = (*$ptr, 1);  // Tuple stores (pointer, uint8), not (struct value, uint8)
```

Only bpftrace basic types and aggregations of those types (like tuples or records containing only basic types) are stored as full values.

### 8.3 Map Declarations

**Map Variables**: Maps persist for the lifetime of bpftrace and are accessible from all action blocks and userspace. Map names start with `@`:

```ebnf
MapDecl = "let" "@" identifier "=" MapType "(" int_lit ")" .
MapType = "hash" | "lruhash" | "percpuhash" | "percpulruhash" .
```

Map types:
- `hash`: Standard hash map (BPF_MAP_TYPE_HASH)
- `lruhash`: LRU hash map with approximate eviction (BPF_MAP_TYPE_LRU_HASH)
- `percpuhash`: Per-CPU hash map (BPF_MAP_TYPE_PERCPU_HASH)
- `percpulruhash`: Per-CPU LRU hash map (BPF_MAP_TYPE_LRU_PERCPU_HASH)

The argument to the map type specifies maximum entries. Maps not explicitly declared default to `hash` type with the `max_map_keys` config variable as the maximum (default 4096).

Examples:

```
let @count = hash(1024);        // Hash map with 1024 max entries
let @cache = lruhash(512);      // LRU hash with 512 max entries
let @percpu = percpuhash(256);  // Per-CPU hash with 256 max entries
```

**Map Keys**: Maps can have scalar keys, single value keys, or multi-value tuple keys:

```
@scalar = value;                 // Scalar map (no key)
@map[pid] = value;              // Single key
@map[pid, comm] = value;        // Multi-value key (tuple)
@map[(pid, comm)] = value;      // Equivalent explicit tuple syntax
```

**Per-Thread Variables**: A common pattern is using maps keyed on `tid` to track per-thread state:

```
kprobe:do_nanosleep {
  @start[tid] = nsecs;
}

kretprobe:do_nanosleep /@start[tid]/ {
  printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000);
  delete(@start[tid]);
}
```

### 8.4 Scope

Identifiers are in scope from the point of declaration to the end of the enclosing block. Each block introduces a new scope.

Variables declared in an inner block shadow variables with the same name in outer blocks:

```
$x = 1;
if (condition) {
  $x = 2;        // Shadows outer $x
  $y = 3;        // Only visible in this block
}
// $x is 1 here (if condition was false) or 2 (if true)
// $y is not accessible here
```

## 9. Expressions

An expression specifies the computation of a value by applying operators and functions to operands.

### 9.1 Operands

Operands denote the elementary values in an expression:

```ebnf
Operand     = Literal | identifier | Variable | Map | "(" Expression ")" .
Variable    = "$" identifier .
Map         = "@" [ identifier ] .
```

### 9.2 Primary Expressions

Primary expressions are the operands for unary and binary expressions:

```ebnf
PrimaryExpr = Operand |
              PrimaryExpr "." identifier |
              PrimaryExpr "." int_lit |
              PrimaryExpr "->" identifier |
              PrimaryExpr "[" Expression "]" |
              PrimaryExpr "(" [ ArgumentList ] ")" .

ArgumentList = Argument { "," Argument } .
Argument = [ identifier "=" ] Expression | "**" Expression .
```

Function and macro calls support three forms of arguments:
- **Positional arguments**: `func($x, $y)`
- **Keyed arguments**: `func(a=$x, b=$y)`
- **Record expansion**: `func(**$rec)` expands a record's fields as keyed arguments

Examples:

```
$x                // Variable
@map              // Map
$struct.field     // Field access
$ptr->field       // Pointer field access
$tuple.0          // Tuple element access
$record.name      // Record field access
$array[index]     // Array/map indexing
func($x, $y)      // Positional arguments
func(a=$x, b=$y)  // Keyed arguments
func(**$rec)      // Record expansion
func($x, b=$y)    // Mixed positional and keyed
```

Argument passing rules:
- Positional arguments must appear before keyed arguments
- Record expansion can appear anywhere and expands all fields as keyed arguments
- Multiple record expansions are allowed and their fields are merged
- If the same key appears multiple times, the last occurrence takes precedence
```

### 9.3 Tuple Literals

A tuple literal constructs a tuple value:

```ebnf
TupleLit = "(" Expression "," Expression { "," Expression } ")" .
```

Examples:

```
(1, 2)
(pid, comm, elapsed)
(1, (2, 3), 4)     // Nested tuples
```

### 9.4 Record Literals

A record literal constructs a record value with named fields:

```ebnf
RecordLit = "(" RecordField { "," RecordField } ")" .
RecordField = identifier "=" Expression .
```

Examples:

```
(a=1, b=2)
(name="hello", count=42, active=true)
(x=pid, y=comm, z=elapsed)
(outer=(inner=1, value=2), flag=true)     // Nested records
```

Field order is not significant - `(a=1, b=2)` is equivalent to `(b=2, a=1)`.

### 9.5 Operators

#### 9.5.1 Operator Precedence

Unary operators have the highest precedence. Binary operators associate left to right. The following list shows operator precedence from highest to lowest:

```
Precedence    Operator
    5         *  /  %  <<  >>  &
    4         +  -  |  ^
    3         ==  !=  <  <=  >  >=
    2         &&
    1         ||
```

#### 9.5.2 Arithmetic Operators

```
+    sum                    integers
-    difference             integers
*    product                integers
/    quotient               integers
%    remainder              integers
```

**Type Promotion**: Operations between different-sized integers implicitly promote the smaller integer to the size of the larger one. Sign is preserved in the promotion:

```
(uint32)5 + (uint8)3   // Converted to (uint32)5 + (uint32)3, results in (uint32)8
(int16)10 - (int8)5    // Converted to (int16)10 - (int16)5, results in (int16)5
```

**Mixed Signedness**: Operations between signed and unsigned integers are allowed only if bpftrace can statically prove a safe conversion is possible. If safe conversion is not guaranteed, the operation is undefined behavior and a warning is emitted.

**Pointer Arithmetic**: Pointers may be used with `+` and `-` operators. For subtraction, the pointer must appear on the left side of the operator.

#### 9.5.3 Bitwise Operators

```
&    bitwise AND            integers
|    bitwise OR             integers
^    bitwise XOR            integers
<<   left shift             integers
>>   right shift            integers
```

#### 9.5.4 Comparison Operators

```
==   equal
!=   not equal
<    less
<=   less or equal
>    greater
>=   greater or equal
```

Comparison operators are defined for:
- **Integers and pointers**: All operators (`<`, `<=`, `>`, `>=`, `==`, `!=`)
- **Strings, integer arrays, and tuples**: Equality operators only (`==`, `!=`)

#### 9.5.5 Logical Operators

```
&&   conditional AND    booleans
||   conditional OR     booleans
!    NOT                booleans
```

Pointers may be used with logical operators; they are considered true when non-null.

### 9.6 Unary Operators

```ebnf
UnaryExpr = PrimaryExpr | unary_op UnaryExpr .
unary_op  = "!" | "-" | "~" | "*" | "&" .
```

```
!    logical NOT
-    negation
~    bitwise NOT
*    dereference
&    address-of
```

### 9.7 Address Operators

The `&` operator generates a pointer to its operand:

```
$x = 42;
$ptr = &$x;      // $ptr is a pointer to $x
```

The `*` operator denotes the variable pointed to by a pointer:

```
$y = *$ptr;      // $y is the value pointed to by $ptr
```

### 9.8 Increment and Decrement

The `++` and `--` operators increment or decrement their operand by 1. They can be used as prefix or suffix operators:

```
$x++;            // Suffix: returns original value, then increments
++$x;            // Prefix: increments, then returns new value
$y--;            // Suffix: returns original value, then decrements
--$y;            // Prefix: decrements, then returns new value
```

The difference between prefix and suffix is the expression's return value:

```
$x = 10;
$y = $x--;       // $y = 10, $x = 9 (returns original value before decrement)

$a = 10;
$b = --$a;       // $a = 9, $b = 9 (returns new value after decrement)
```

**Important notes**:
- These operators can only be used on variables (not expressions)
- Maps are implicitly declared and initialized to 0 if not already defined
- Scratch variables must be initialized before using these operators
- Using `++`/`--` on shared global variables can lose updates due to race conditions

### 9.9 Block Expressions

A block can be used as an expression if its last statement is an expression without a trailing semicolon:

```
let $x = {
  let $y = 1;
  $y + 1
};
// $x is 2
```

Block expressions can be used anywhere an expression is expected. The value of the block is the value of its final expression.

**Discarded Expressions**: bpftrace warns about expressions whose values are discarded:

```
{ 1 }                  // Warning: discarded expression value
$a = { 1 }             // No warning: value is used
has_key(@a, 1);        // Warning: discarded expression value
$b = has_key(@a, 1);   // No warning: value is used
```

The warning can be silenced using the discard expression:

```
_ = has_key(@a, 1);    // No warning: explicitly discarded
```

### 9.10 Conditional Expressions

The ternary operator provides conditional expressions:

```ebnf
ConditionalExpr = Expression "?" Expression ":" Expression .
```

Example:

```
$max = $a > $b ? $a : $b;
```

### 9.11 Intrinsic Calls

Intrinsic function calls are compile-time or runtime operations:

```ebnf
IntrinsicCall = "sizeof" "(" Type ")" |
                "offsetof" "(" Type "," identifier ")" |
                "typeof" "(" Expression ")" |
                "typeinfo" "(" ( Type | Expression ) ")" .
```

Examples:

```
sizeof(int64)              // Returns 8
offsetof(struct Point, x)  // Returns offset of field x
typeof($x)                 // Returns type of expression
typeinfo(struct Point)     // Returns type information
```

## 10. Statements

Statements control execution flow.

```ebnf
Statement = Declaration | SimpleStmt | ReturnStmt | BreakStmt |
            ContinueStmt | Block | IfStmt | ForStmt | WhileStmt | UnrollStmt .

SimpleStmt = EmptyStmt | ExprStmt | Assignment .
```

### 10.1 Empty Statements

An empty statement does nothing:

```ebnf
EmptyStmt = .
```

### 10.2 Expression Statements

An expression statement evaluates an expression for its side effects:

```ebnf
ExprStmt = Expression .
```

### 10.3 Assignments

```ebnf
Assignment = Variable assign_op Expression |
             Map "[" Expression "]" assign_op Expression .

assign_op = "=" | "+=" | "-=" | "*=" | "/=" | "%=" |
            "<<=" | ">>=" | "&=" | "|=" | "^=" .
```

The compound assignment operators are syntactic sugar for combining an operation with assignment. For example, `@count += 1` is equivalent to `@count = @count + 1`.

These operators work on both scratch variables and maps:

```
$x = 42;
$y += 10;        // $y = $y + 10
@map[key] = value;
@count[pid] += 1;   // @count[pid] = @count[pid] + 1
```

### 10.4 If Statements

```ebnf
IfStmt = "if" "(" Expression ")" Block [ "else" ( IfStmt | Block ) ] .
```

Examples:

```
if ($x > 0) {
  print("positive");
}

if ($x > 0) {
  print("positive");
} else if ($x < 0) {
  print("negative");
} else {
  print("zero");
}
```

### 10.5 While Statements

**Note**: While loops are deprecated and may be removed in future versions. Use `for` loops with integer ranges instead, as these are more easily verified to be bounded.

```ebnf
WhileStmt = "while" "(" Expression ")" Block .
```

Example:

```
while ($i < 10) {
  print($i);
  $i++;
}
```

The `break` and `continue` statements control execution within loops:

```
while (condition) {
  if (skip_condition) {
    continue;    // Skip to next iteration
  }
  if (exit_condition) {
    break;       // Exit loop
  }
  // loop body
}
```

### 10.6 For Statements

For statements can iterate over map entries or integer ranges:

```ebnf
ForStmt = "for" "(" Variable ":" Expression ")" Block .
```

**Map Iteration**: When iterating over a map, the loop variable is initialized with a tuple `(key, value)`:

```
@map[10] = 20;
for ($kv : @map) {
  print($kv.0);  // Key: 10
  print($kv.1);  // Value: 20
}
```

For maps with multiple keys, the loop variable contains a nested tuple `((key1, key2, ...), value)`:

```
@map[10, 11] = 20;
for ($kv : @map) {
  print($kv.0.0);  // First key: 10
  print($kv.0.1);  // Second key: 11
  print($kv.1);    // Value: 20
}
```

**Integer Range Iteration**: The loop variable is initialized with each integer in the range, inclusive of start and exclusive of end:

```
for ($i : 0..10) {
  print($i);  // Prints 0, 1, 2, ..., 9
}

for ($cpu : 0..ncpus) {
  print($cpu);  // Iterate over CPU indices
}
```

**Range Evaluation**: The start and end values are evaluated once at loop initialization, not on each iteration:

```
$a = 10;
for ($i : 0..$a) {
  print($i);
  $a--;  // Does not affect loop range
}
// Prints 0 through 9
```

**Control Flow**: Both map and range iteration support `break`, `continue`, and `return` statements.

Map iteration requires Linux kernel 5.13+.

### 10.7 Unroll Statements

Unroll statements repeat a block a fixed number of times at compile-time:

```ebnf
UnrollStmt = "unroll" "(" int_lit ")" Block .
```

Example:

```
unroll(5) {
  print("loop");
}
```

This is equivalent to repeating the block 5 times. The unroll count must be a compile-time constant.

### 10.8 Return Statements

A return statement terminates execution of the current probe (not the entire bpftrace program):

```ebnf
ReturnStmt = "return" .
```

Example:

```
kprobe:do_nanosleep {
  if (pid != target_pid) {
    return;          // Exit this probe, not the entire program
  }
  // Only executed if pid == target_pid
}
```

The `return` statement differs from `exit()` in that it only exits the current probe, while `exit()` terminates the entire bpftrace program.

### 10.9 Break and Continue Statements

```ebnf
BreakStmt    = "break" .
ContinueStmt = "continue" .
```

These statements control loop execution:
- `break` exits the innermost `while` or `for` loop
- `continue` skips to the next iteration of the innermost loop

## 11. Intrinsic Functions

Intrinsic functions are built into the language and provide compile-time and runtime capabilities beyond what can be expressed in the language itself.

### 11.1 Compile-Time Intrinsics

#### 11.1.1 comptime

The `comptime` intrinsic evaluates an expression at compile-time:

```
comptime expression
```

The expression must be evaluable at compile-time. This is useful for conditional compilation and constant folding.

Example:

```
$size = comptime sizeof(int64) * 10;  // Evaluates to 80 at compile-time
```

#### 11.1.2 is_literal

The `is_literal` intrinsic tests whether an expression is a compile-time constant:

```
is_literal(expression)
```

Returns `true` if the expression can be evaluated at compile-time, `false` otherwise.

Example:

```
is_literal(42)        // true - literal constant
is_literal($x + 5)    // false - depends on runtime variable
```

### 11.2 Type Intrinsics

#### 11.2.1 sizeof

Returns the size in bytes of a type:

```
sizeof(Type)
```

Example:

```
sizeof(int64)           // Returns 8
sizeof(struct Point)    // Returns size of Point struct
```

#### 11.2.2 offsetof

Returns the offset in bytes of a field within a struct:

```
offsetof(StructType, field)
```

Example:

```
offsetof(struct Point, y)  // Returns offset of field y
```

#### 11.2.3 typeof

Returns the type of an expression:

```
typeof(expression)
```

This can be used in type casts and declarations.

Example:

```
$x = 42;
$y = (typeof($x))100;  // $y has the same type as $x
```

#### 11.2.4 typeinfo

Returns detailed type information:

```
typeinfo(Type)
typeinfo(expression)
```

This provides extended type metadata beyond what `typeof` returns.

## 12. Macros

Macros provide compile-time code expansion and reuse.

### 12.1 Macro Declarations

```ebnf
MacroDecl = "macro" identifier "(" [ MacroParams ] ")" Block .
MacroParams = MacroParam { "," MacroParam } .
MacroParam = Variable | Map | identifier .
```

### 12.2 Macro Definitions

Macros are defined with the `macro` keyword:

```
macro add_one($x) {
  $x + 1
}
```

**Hygienic Macros**: bpftrace macros are "hygienic macros" - the macro body may only access maps and external variables that are explicitly passed in through parameters. This prevents unintended access to external state. The macro body can create new variables which exist only inside the body.

A macro's parameter signature specifies how an argument will be used:
- **Variable parameters** (prefixed with `$`): Accept scratch variables that may be mutated
- **Expression parameters** (unprefixed identifier): Accept expressions that are inserted wherever the parameter is used
- **Map parameters** (prefixed with `@`): Accept maps that may be mutated

Examples:

```
macro example($var, expr, @map) {
  $var += 1;       // Mutates the scratch variable
  expr;            // Expression inserted here
  @map[pid] = 1;   // Mutates the map
}

// Valid calls:
example($x, 1 + 2, @counts);        // All arguments match parameter types
example($y, pid, @stats);            // Expression can be an identifier
example($z, { print("hi") }, @data); // Expression can be a block
```

Variables and maps can also be used for expression parameters and would be equivalent to using a block expression.

**Invalid Macro Usage**: Macros cannot access external state not passed as parameters:

```
macro unhygienic_access() {
  @x++                         // ERROR: @x not passed in
}

macro wrong_parameter_type($x) {
  $x++
}

begin {
  @x = 1;
  unhygienic_access();         // ERROR: cannot access @x

  wrong_parameter_type(@x);    // ERROR: expects scratch variable, got map
  wrong_parameter_type(1 + 1); // ERROR: expects scratch variable, got expression
}
```

**Expression Evaluation**: Expression parameters are inserted where used, which may result in multiple evaluations. To evaluate once, bind to a variable:

```
macro add_one(x) {
  let $x = x;      // Evaluates expression once
  $x + 1
}

### 12.3 Macro Expansion

Macros are expanded at compile-time by substituting arguments into the macro body. The last expression in the macro body is the macro's value:

```
macro square($x) {
  $x * $x
}

$result = square(5);  // Expands to: 5 * 5
```

Macros can call other macros:

```
macro add_two($x) {
  add_one(add_one($x))
}
```

## 13. Subprograms

Subprograms are reusable functions that can be called from probe bodies.

### 13.1 Subprogram Declarations

```ebnf
SubprogDecl = "fn" identifier "(" [ SubprogParams ] ")" ":" Type Block .
SubprogParams = SubprogParam { "," SubprogParam } .
SubprogParam = identifier ":" Type .
```

### 13.2 Subprogram Definitions

Subprograms are defined with the `fn` keyword:

```
fn square(x: int64): int64 {
  return x * x;
}
```

Subprogram parameters are explicitly typed:

```
fn add(a: int64, b: int64): int64 {
  return a + b;
}
```

### 13.3 Subprogram Calls

Subprograms are called like macros but are compiled to separate eBPF functions:

```
$result = square(5);
```

Unlike macros, subprograms:
- Have explicit parameter types
- Use `return` to return values
- Are compiled to separate functions
- Can be recursive (subject to eBPF limitations)

### 13.4 Async Subprograms

Async subprograms provide asynchronous execution in user context. They are defined with the `async fn` keyword:

```ebnf
AsyncSubprogDecl = "async" "fn" identifier "(" [ SubprogParams ] ")" ":" Type Block .
```

**Async Subprogram Behavior**:
- Execute in user context (not in the eBPF probe context)
- Return an async ID representing the pending computation
- Async values are opaque and cannot be directly inspected
- When passed to other async subprograms, they are automatically unpacked

**Example**:

```
async fn process_data(value: int64): int64 {
  // Runs in user context
  return value * 2;
}

async fn chain_processing(input: int64): int64 {
  // The async value from process_data is automatically unpacked
  $intermediate = process_data(input);  // Returns async ID
  return $intermediate + 10;             // Automatic unpacking
}

kprobe:vfs_read {
  $async_id = process_data(arg2);  // Returns async ID (opaque)
  // Cannot directly inspect $async_id, must pass to another async subprogram
}
```

Async subprograms enable expensive computations to be deferred to user context, avoiding eBPF execution time limits.

### 13.5 Nested and Anonymous Subprograms

Nested subprograms can appear as statements within blocks, including macro bodies. They automatically capture variables from the enclosing scope and can also accept explicit parameters.

**Syntax**:

```ebnf
NestedSubprog = "fn" identifier "(" [ SubprogParams ] ")" ":" Type Block .
```

**Capture Semantics**: Nested subprograms automatically capture any referenced variables from the current scope, similar to how `for` loops work. Variables are passed via an implicit context.

**Example**:

```
macro process_items($data) {
  // Nested subprogram with automatic capture
  fn helper(item: int64): int64 {
    // Automatically captures $data from outer scope
    return item + $data;
  }

  // Can be invoked multiple times
  $result1 = helper(10);
  $result2 = helper(20);
  return $result1 + $result2;
}

kprobe:vfs_read {
  $value = 5;

  // Nested subprogram in probe body
  fn double_and_add(x: int64): int64 {
    // Automatically captures $value from outer scope
    return x * 2 + $value;
  }

  print(double_and_add(10));  // prints 25 (10 * 2 + 5)
  print(double_and_add(15));  // prints 35 (15 * 2 + 5)
}
```

**Anonymous Subprograms**: Subprograms without explicit names can be used inline:

```
kprobe:vfs_write {
  $transform = fn(x: int64): int64 {
    return x * x;
  };

  print($transform(5));   // prints 25
  print($transform(10));  // prints 100
}
```

Nested and anonymous subprograms provide a way to organize code within probes and macros while maintaining access to the enclosing scope.

## 14. Imports

The import mechanism allows including external definitions.

### 14.1 Import Statements

```ebnf
ImportDecl = "import" string_lit .
```

Example:

```
import "common.bt"
```

Imported files are processed as if their contents were included at the point of the import statement.

## 15. Program Structure

A bpftrace program consists of:

```ebnf
Program = [ Preamble ] [ Config ] { RootStmt } .
Preamble = { PreprocessorDirective | StructDecl } .
Config = "config" "=" "{" { ConfigItem } "}" .
RootStmt = MacroDecl | MapDecl | SubprogDecl | Probe .
```

### 15.1 Preamble

The preamble contains optional elements that appear before probe definitions:

- **Preprocessor directives**: `#include`, `#define`, etc.
- **Type definitions**: struct, union, enum declarations
- **Config block**: Configuration variable settings
- **Map declarations**: Global map definitions

Example:

```
#include <linux/path.h>
#define RED "\033[31m"

struct Point {
  int x;
  int y;
}

config = {
  stack_mode = perf;
}

let @count = lruhash(100);
```

**Preprocessor directives** are passed through to Clang for processing. These are typically used to include kernel headers for struct definitions.

**BTF Integration**: If the kernel has BTF (BPF Type Format) support, kernel types are automatically available without needing to include headers. See [BTF Support](#165-btf-support) for details. It is not recommended to mix BTF and header file definitions as this can cause redefinition conflicts.

### 15.2 Config Block

The config block sets configuration variables. Configuration must appear before any probe definitions:

```
config = {
  stack_mode = perf;
  max_map_keys = 2048;
}
```

**Config Variable Names**: Config variable names can use either environment variable format or lowercase format without the `BPFTRACE_` prefix. For example, `BPFTRACE_STACK_MODE`, `STACK_MODE`, and `stack_mode` are equivalent.

**Environment Variable Precedence**: Environment variables for the same config take precedence over those set inside a script config block.

**Common Config Variables**:
- `max_strlen` (default: 1024): Maximum length in bytes for `str()`, `buf()`, and `path()` values
- `max_map_keys` (default: 4096): Maximum number of keys in a map
- `max_probes` (default: 1024): Maximum number of probes to attach
- `stack_mode` (default: bpftrace): Output format for `ustack` and `kstack` (options: `bpftrace`, `perf`, `raw`)
- `missing_probes` (default: error): How to handle missing probes (options: `error`, `warn`, `ignore`)
- `print_maps_on_exit` (default: true): Whether to automatically print maps at program exit

### 15.3 Probes

A probe consists of probe specifications, an optional predicate (filter), and an action block:

```ebnf
Probe = ProbeList [ Predicate ] Block .
ProbeList = ProbeSpec { "," ProbeSpec } .
ProbeSpec = identifier [ ":" identifier [ ":" identifier ]* ] .
Predicate = "/" Expression "/" .
```

**Probe Specification**: Probes start with a provider (e.g., `kprobe`) followed by colon-separated options. An optional name may precede the provider with an equals sign (e.g., `name=provider:...`), reserved for internal use and future features.

**Filters/Predicates**: Filters can be added after probe names. The probe still fires, but the action is skipped unless the filter evaluates to true:

```
kprobe:vfs_read /arg2 < 16/ {
  printf("small read: %d byte buffer\n", arg2);
}

kprobe:vfs_read /comm == "bash"/ {
  printf("read by %s\n", comm);
}
```

**Multiple Probes**: Multiple probes can share the same action by using comma-separated lists:

```
kprobe:tcp_reset,kprobe:tcp_v4_rcv {
  printf("Entered: %s\n", probe);
}
```

**Wildcards**: Probe names support wildcard matching:

```
kprobe:tcp_* {
  printf("Entered: %s\n", probe);
}

// Wildcards can be combined with explicit probes
kprobe:tcp_reset,kprobe:*socket* {
  printf("Entered: %s\n", probe);
}
```

**Missing Probes**: By default, bpftrace requires all probes to attach successfully or returns an error. This can be changed using the `missing_probes` config variable (options: `error`, `warn`, `ignore`).

**Common Probe Types**:
- `kprobe`/`kretprobe` (short: `k`/`kr`): Kernel function entry/return
- `tracepoint` (short: `t`): Kernel static tracepoints
- `uprobe`/`uretprobe` (short: `u`/`ur`): User-level function entry/return
- `fentry`/`fexit` (short: `f`/`fr`): Kernel functions with BTF support
- `begin`/`end`: Built-in events (before/after probe attachment)
- `interval` (short: `i`): Timed output
- `profile` (short: `p`): Timed sampling

## 16. Execution Model

### 16.1 Compilation

bpftrace programs are compiled to eBPF bytecode through the following stages:

1. Lexical analysis and parsing
2. Semantic analysis and type checking
3. Code generation to eBPF bytecode
4. Loading into the Linux kernel
5. Attachment to probe points

### 16.2 Execution

When a probe fires:

1. The eBPF program executes in kernel space
2. Program has access to probe context and global maps
3. Program updates maps or generates events
4. Execution completes and control returns to the kernel

### 16.3 Invocation Modes

Operations can occur in three modes:

- **Synchronous**: Executed immediately in kernel space during probe execution
- **Asynchronous**: Executed later in user space after probe execution
- **Compile-time**: Evaluated during compilation

Asynchronous operations can lead to race conditions as map updates may occur before user space processes the event.

### 16.4 Address Spaces

bpftrace distinguishes between kernel and user address spaces. Pointers are associated with an address space, determining how memory is accessed when dereferenced:

- Kernel pointers access kernel memory
- User pointers access user process memory

The address space is determined by the pointer's origin (e.g., kernel struct vs user buffer). bpftrace attempts to automatically set the correct address space based on the probe type, but in unclear cases the address space can be explicitly set using the `kptr()` and `uptr()` builtins.

### 16.5 BTF Support

If the kernel has BTF (BPF Type Format) support, kernel types are automatically available without needing to include headers. BTF provides type information that bpftrace uses for:

- Automatic availability of kernel struct definitions
- Accurate field offset calculations
- Kernel function signature information

**Benefits of BTF**:
- Type definitions never get out of sync with the running kernel
- Less susceptible to parsing failures than C headers
- Automatic support for kernel module types (Linux 5.11+ with CONFIG_DEBUG_INFO_BTF_MODULES)

**Requirements**:
- Linux 4.18+ with CONFIG_DEBUG_INFO_BTF=y
- bpftrace v0.9.3+ with BTF support

**BTF Detection**: The preprocessor macro `BPFTRACE_HAVE_BTF` is defined if BTF is detected, allowing scripts to conditionally use BTF features.

It is not recommended to mix definitions from BTF and header files, as this can cause redefinition conflicts.

## 17. Limitations

bpftrace inherits limitations from eBPF:

1. **Stack size**: Limited to 512 bytes
2. **No floating-point**: Floating-point arithmetic is not supported
3. **Bounded loops**: Loops must have a compile-time determinable bound
4. **No recursion**: Recursive function calls are not supported
5. **Program size**: Maximum program size is limited by the kernel
6. **Verifier constraints**: All programs must pass the eBPF verifier

These limitations exist to ensure safety and bounded execution time in the kernel.

## Appendix A: Aggregate Types

Aggregate types are library-defined types built using the fundamental type system. These examples demonstrate how the language features enable complex type patterns without requiring hardcoded builtin types.

### A.1 Statistical Aggregates

Statistical aggregates can be expressed using records with named fields:

```
// Minimum value tracker
type min_t = (value: int64)

// Maximum value tracker
type max_t = (value: int64)

// Sum accumulator
type sum_t = (total: int64)

// Average calculator
type avg_t = (sum: int64, count: int64)

// Complete statistics
type stats_t = (count: int64, sum: int64, min: int64, max: int64)

// Count tracker
type count_t = (n: int64)
```

Usage example:

```
@stats = (count=0, sum=0, min=0, max=0);

kprobe:vfs_read {
  @stats.count++;
  @stats.sum += arg2;
  @stats.min = @stats.count == 1 ? arg2 : (@stats.min < arg2 ? @stats.min : arg2);
  @stats.max = @stats.max > arg2 ? @stats.max : arg2;
}
```

### A.2 Special Value Types

Special value types can be represented using records or appropriately-sized buffers:

```
// MAC address (6 bytes)
type macaddr_t = uint8[6]

// Process name (typically 16 bytes in Linux)
type comm_t = string[16]

// Username (typically up to 32 characters)
type username_t = string[32]

// Cgroup path
type cgroup_path_t = string[256]

// Timestamp with nanosecond precision
type timestamp_t = uint64

// Kernel/user stack traces (represented as arrays of addresses)
type kstack_t = uint64[127]
type ustack_t = uint64[127]

// Symbol information (address and name)
type ksym_t = (addr: uint64, name: string[256])
type usym_t = (addr: uint64, name: string[256])
```

### A.3 Histogram Types

Histogram types can be expressed using maps with specific key and value types:

```
// Linear histogram: maps bucket index to count
type lhist_t = @lhist: hash<int64, int64>

// Log2 histogram: maps power-of-two bucket to count
type hist_t = @hist: hash<int64, int64>

// Time series: maps timestamp to value
type tseries_t = @tseries: hash<uint64, int64>
```

Usage example:

```
@latency: hash<int64, int64> = hash(128);

kprobe:do_sys_open {
  @start[tid] = nsecs;
}

kretprobe:do_sys_open /@start[tid]/ {
  $duration = nsecs - @start[tid];
  $bucket = $duration / 1000;  // Microsecond buckets
  @latency[$bucket]++;
  delete(@start[tid]);
}
```

### A.4 Probe Context Type

Probe information can be represented as a record:

```
type probe_t = (
  provider: string[32],    // e.g., "kprobe", "tracepoint"
  function: string[128],   // Function or event name
  location: uint64         // Address or location
)
```

These examples demonstrate how the fundamental type system (integers, buffers, structs, records, tuples, pointers, and arrays) can express complex aggregate patterns. The language does not hardcode these types; instead, they emerge naturally from composing the basic building blocks.

## Appendix B: Deprecated Features

This appendix documents deprecated language features that may be removed in future versions of bpftrace.

### B.1 While Loops (Deprecated)

While loops are deprecated and may be removed in future versions. They are replaced by for loops with ranges, which are more easily proven to be bounded by the eBPF verifier.

**Deprecated:**

```
while ($i < 10) {
  print($i);
  $i++;
}
```

**Recommended:**

```
for ($i : 0..10) {
  print($i);
}
```

For loops with ranges provide several advantages:
- Easier for the verifier to prove bounded execution
- Clearer iteration bounds at a glance
- Less prone to infinite loop errors


