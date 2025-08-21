# Custom Malloc Implementation

A custom memory allocator implementation in C that provides an alternative to the standard `malloc()`, `free()`, and `realloc()` functions. This project demonstrates advanced memory management techniques including free list management, block coalescing, and memory corruption detection.

## 🚀 Features

- **Custom Memory Allocator**: Implements `my_malloc()`, `my_free()`, and `my_realloc()`
- **Free List Management**: Efficient free block tracking using multiple free lists
- **Block Coalescing**: Automatically merges adjacent free blocks to reduce fragmentation
- **Memory Corruption Detection**: Canary values to detect buffer overflows
- **Configurable Arena Size**: Adjustable memory pool size via compile-time constants
- **Comprehensive Testing**: Extensive test suite covering edge cases and error conditions
- **Performance Optimized**: Efficient allocation and deallocation algorithms

## 🏗️ Architecture

### Memory Block Structure
Each memory block contains a header with metadata:
- **Size and State**: Combined field storing block size and allocation state
- **Left Size**: Size of the block to the left in memory
- **Free List Pointers**: Next/previous pointers when block is free
- **User Data**: Actual memory available to the user

### Free List Management
- Multiple free lists organized by size classes
- Fast allocation for common block sizes
- Automatic block splitting and coalescing
- Efficient free block insertion and removal

### Memory States
- `UNALLOCATED`: Block is free and available for allocation
- `ALLOCATED`: Block is currently in use
- `FENCEPOST`: Special marker for memory boundary detection

## 📁 Project Structure

```
lab1-src/
├── myMalloc.c          # Main malloc implementation
├── myMalloc.h          # Header file with declarations and constants
├── testing.c           # Testing framework implementation
├── testing.h           # Testing framework header
├── Makefile            # Build configuration
├── runtest.py          # Python test runner script
├── examples/           # Example programs demonstrating usage
│   ├── arch_ex.c       # Architecture example
│   ├── composite_ex.c  # Composite object example
│   └── constructor_ex.c # Constructor example
├── tests/              # Comprehensive test suite
│   ├── test_simple*.c  # Basic functionality tests
│   ├── test_*.c        # Various edge case tests
│   └── expected/       # Expected test outputs
└── utils/              # Utility scripts and tools
```




### Test Categories
- **Basic Functionality**: Simple allocation/deallocation
- **Edge Cases**: Zero-size allocations, large allocations
- **Error Handling**: Double free, corrupted memory detection
- **Performance**: Random allocation patterns, memory fragmentation
- **Robustness**: Memory corruption, out-of-memory scenarios

### Test Output
Tests generate output files that can be compared against expected results:
- `test_results*.txt`: Actual test outputs
- `test_results*expected.txt`: Expected test outputs
- `resultsimple*.txt`: Simple test results

## 🔍 Key Implementation Details

### Memory Layout
```
[Header][User Data][Header][User Data]...
  ^       ^          ^       ^
  |       |          |       |
Block1  Data1     Block2   Data2
```

### Free List Organization
- Free lists are organized by size classes
- Each list contains blocks of similar sizes
- Fast allocation for common block sizes
- Automatic block splitting for optimal fit

### Coalescing Algorithm
- Automatically merges adjacent free blocks
- Reduces memory fragmentation
- Maintains free list consistency
- Improves allocation efficiency

## 📊 Performance Characteristics

- **Allocation Time**: O(1) for common block sizes, O(n) for large blocks
- **Deallocation Time**: O(1) with automatic coalescing
- **Memory Overhead**: ~16 bytes per allocated block
- **Fragmentation**: Minimized through coalescing and splitting

## 🚨 Error Handling

The allocator includes several safety features:
- **Canary Values**: Detect buffer overflows
- **State Validation**: Verify block integrity
- **Boundary Checking**: Prevent invalid memory access
- **Graceful Degradation**: Handle out-of-memory conditions

## 🤝 Contributing

This project is part of a CS252 course assignment. The implementation demonstrates:
- Advanced C programming techniques
- Memory management algorithms
- Testing and validation strategies
- Performance optimization

## 📝 License

This project is created for educational purposes as part of CS252 coursework.


