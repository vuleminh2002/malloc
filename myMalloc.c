#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#include "myMalloc.h"

#define MALLOC_COLOR "MALLOC_DEBUG_COLOR"

static bool check_env;
static bool use_color;

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

//Extra helper function
//find the require block size for allocating a block
static size_t require_block_size(size_t raw_size);
//find the index on the freelist array
static int get_idx_freelist(int ind);
//find an appropriate block
static header * get_appropriate_block(header * sentinal, size_t require_size);
//allocate a new chunk and coalesing
static header * allocate_new_chunk(size_t size);
//function to insert a block into a free list.
void insert_block(header * block);
// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();

static bool isMallocInitialized;

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}

/**
 * @brief Helper function to get the header to the left of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencpost)
 */
static header * allocate_chunk(size_t size) {
  //printf("%s\n", "hello\n");
  void * mem = sbrk(size);

  if (mem == (void *) -1) {
        errno = ENOMEM;      // Throw "out of memory" error
        return NULL;         // Return NULL to indicate failure
    }

  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}

void insert_block(header * block){
   if (!block) return; // NULL check to avoid segmentation faults

    // Determine the appropriate free list index for the block
    int idx = get_idx_freelist((get_size(block) - ALLOC_HEADER_SIZE) / 8 - 1);

    // Get the sentinel node for the corresponding free list
    header *sentinel = &freelistSentinels[idx];

    // Insert the block at the beginning of the free list(empty list)
    if (sentinel->next == sentinel) {
        // Free list is empty
        sentinel->next = block;
        sentinel->prev = block;
        block->next = sentinel;
        block->prev = sentinel;
    } else {
        // Free list is not empty
        block->next = sentinel->next;
        block->prev = sentinel;
        sentinel->next->prev = block;
        sentinel->next = block;
    }
    
  }
  
static header * allocate_new_chunk(size_t size){
  header *new_chunk = allocate_chunk(size);
    if (new_chunk == NULL) {
        return NULL; // Allocation failed
    }
    header * left_fencepost = get_header_from_offset(new_chunk, -ALLOC_HEADER_SIZE);
    header * right_fencepost = get_right_header(new_chunk);

    header * last_fencepost = get_left_header(left_fencepost);
  
    //check if two chunks are adjacent
    if(last_fencepost == lastFencePost){
      //case 1 if the previous block is unallocated
      header * leftHeader = get_left_header(lastFencePost);
      if(get_state(leftHeader) == UNALLOCATED){
        size_t newSize = get_size(leftHeader) + get_size(new_chunk) + 2* ALLOC_HEADER_SIZE;
        set_size(leftHeader, newSize);
        set_state(leftHeader, UNALLOCATED);
        right_fencepost->left_size = newSize;
        //dropping the block
        leftHeader->next->prev = leftHeader->prev;
        leftHeader->prev->next = leftHeader->next;
        //readd it
        insert_block(leftHeader);
        lastFencePost = right_fencepost;
        return leftHeader;

      }
      if(get_state(leftHeader) == ALLOCATED){
         
        //case 2 if the previous block is allocated
        header * newHeader = last_fencepost;
        size_t newSize = get_size(new_chunk) + (2 * ALLOC_HEADER_SIZE);
        set_size(newHeader, newSize);
        set_state(newHeader, UNALLOCATED);
        right_fencepost->left_size = newSize;
        insert_block(newHeader);
        lastFencePost = right_fencepost;
        return newHeader;
      }
    }
    //two chunks are not adjacent
    else{
      //printf("size of new chunk%zu\n", new_chunk->size_state);
          insert_block(new_chunk);
          lastFencePost = right_fencepost;
          insert_os_chunk(left_fencepost);
          return new_chunk;

    }

    
}

static size_t require_block_size(size_t raw_size) {
  size_t size = ((raw_size + 7+ ALLOC_HEADER_SIZE)/8)*8;
  if (size > sizeof(header)){
    return size;
  }
  return sizeof(header);
}

static int get_idx_freelist(int ind){
  if (ind >= N_LISTS - 1){
    return N_LISTS - 1;
  }
  return ind;
}

static header * get_appropriate_block(header * sentinal, size_t required_size){
  header * current = sentinal->next;
  while(current != sentinal){
    if(get_size(current) >= required_size){
     
      return current;
    }
    current = current->next;
  }
  return NULL;
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation
  if (raw_size == 0){
    return NULL;
  }
  size_t required_size = require_block_size(raw_size);
  
  int ind = ((required_size-ALLOC_HEADER_SIZE)/8)-1;
  int idx = get_idx_freelist(ind);
          

  header * block = NULL;
  //step 2: find appropriate free list
  for(int i = idx; i < N_LISTS; i++){
    header * sentinal = &freelistSentinels[i];
    //if the final list
    if (i == N_LISTS - 1){
      for (header *cur = sentinal->next; cur != sentinal; cur = cur->next) {
        if (get_size(cur) >= required_size) {
            block = cur;
              break;
        }
      }
    }
    //if not the final list 
    else if(sentinal->next != sentinal){
      block = get_appropriate_block(sentinal ,required_size);
    }
    if(block != NULL){
        break;
      }
  }
  //allocate a new chunk if block is null
   if (block == NULL) {
        header * newChunk = allocate_new_chunk(ARENA_SIZE);
        if (newChunk == NULL) {
            // sbrk() failed -> errno is ENOMEM
            return NULL;  
        }
        // Now that we have a new chunk, run allocate_object() again:
        return allocate_object(raw_size);
    }


  //step 3: allocating
  if(block!= NULL){
    //if the block size is equal the required size
      size_t block_size = get_size(block);

    if(required_size == block_size || block_size - required_size < sizeof(header)){
      set_state(block, ALLOCATED);
      block->next->prev = block->prev;
      block->prev->next = block->next;
      return (header*)block->data;
    }
      
     // Case 2: Block is larger and needs to be split
     if (block_size > required_size) {
      // Update the current block's size
      set_size(block, block_size - required_size);
      
                   
      // Create a new header for the allocated block
      char *new_pointer = (char *)block + get_size(block);
      header *allocated_block = (header *)new_pointer;

      // Initialize the new block's metadata
      set_size(allocated_block, required_size);
      allocated_block->left_size = get_size(block);
      set_state(allocated_block, ALLOCATED);

      // Update the right neighbor's left_size
      char *right_pointer = (char *)allocated_block + get_size(allocated_block);
      header *right_header = (header *)right_pointer;
      right_header->left_size = get_size(allocated_block);

      // Reinsert the remaining block into the appropriate freelist
      int new_listidx = get_idx_freelist((get_size(block) - ALLOC_HEADER_SIZE) / 8 - 1);
      if (new_listidx != idx) {
        block->next->prev = block->prev;
        block->prev->next = block->next;

      insert_block(block);
      
      }
      return (header*)allocated_block->data;
  }
}
}

/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}
/**
 * determine if the block is in the final freelist
 */
static inline bool final_freelist(header * header){
  return get_size(header) >= (N_LISTS+2)*sizeof(size_t);
}
/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */

/**
 * helper function to remove a block from the freelist
 */
static inline void remove_from_freelist(header * hdr) {
  int idx = get_idx_freelist((get_size(hdr) - ALLOC_HEADER_SIZE) / 8 - 1);

  idx = idx > (N_LISTS-1)? N_LISTS-1 : idx;

  header * sentinal = &freelistSentinels[idx];
  for (header * cur = sentinal->next; cur != sentinal; cur = cur->next) {
    if (cur == hdr) {
      cur->prev->next = cur->next;
      cur->next->prev = cur->prev; 
    }
  }
}
static inline void deallocate_object(void * p) {
  // TODO implement deallocation
  if (p == NULL) {
        return; // Freeing NULL is a no-op
  }

    // Retrieve the block's header
  header * hdr = ptr_to_header(p);   

    //check for double free
	if (get_state(hdr) == UNALLOCATED) {
		printf("Double Free Detected\n");
		assert(false);
		exit(1);
	}
  set_state(hdr, UNALLOCATED);
    // Get left and right neighbors
    header *left_neighbor = get_left_header(hdr);
    header *right_neighbor = get_right_header(hdr);

    bool left_unallocated = false;
    bool right_unallocated = false;
    if(get_state(left_neighbor) == UNALLOCATED){
      left_unallocated = true;
    }
    if(get_state(right_neighbor) == UNALLOCATED){
      right_unallocated = true;
    }
    //case 1: both left and right are unallocated.
    if(left_unallocated && right_unallocated){
      size_t newSize = get_size(left_neighbor) + get_size(right_neighbor) +get_size(hdr);
      if(!final_freelist(left_neighbor)){
        remove_from_freelist(left_neighbor);
      }
      set_size(left_neighbor, newSize);
      hdr = left_neighbor;
      get_right_header(right_neighbor)->left_size = newSize;
      remove_from_freelist(right_neighbor);
    }
    //case 2:only the left block is unallocated
    else if(left_unallocated && !right_unallocated ){
      size_t newSize = get_size(left_neighbor) + get_size(hdr);
      if(!final_freelist(left_neighbor)){
        remove_from_freelist(left_neighbor);
      }
      set_size(left_neighbor, newSize);
      get_right_header(hdr)->left_size = newSize;
      hdr = left_neighbor;
    }//case 3: coalesce with the right neighbor only
    else if (!left_unallocated && right_unallocated){
      size_t newSize = get_size(hdr) + get_size(right_neighbor);
      if(!final_freelist(right_neighbor)){
        remove_from_freelist(right_neighbor);
      }
      set_size(hdr, newSize);
      get_right_header(right_neighbor)->left_size = newSize;
    }
    
    int idx = get_idx_freelist((get_size(hdr) - ALLOC_HEADER_SIZE) / 8 - 1);
    if (idx >= N_LISTS - 1) {
      if(!left_neighbor && !right_neighbor){
        insert_block(hdr);
      }else{
        return;
      }
        // If block belongs in the final free list, leave it as is
        
    } else {
        // Reinsert the block into the appropriate free list
        insert_block(hdr);
    }
    
   
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}

/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {
  void * mem = my_malloc(size);
  memcpy(mem, ptr, size);
  my_free(ptr);
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}

/**
 * @brief Print just the block's size
 *
 * @param block The block to print
 */
void basic_print(header * block) {
	printf("[%zd] -> ", get_size(block));
}

/**
 * @brief Print just the block's size
 *
 * @param block The block to print
 */
void print_list(header * block) {
	printf("[%zd]\n", get_size(block));
}

/**
 * @brief return a string representing the allocation status
 *
 * @param allocated The allocation status field
 *
 * @return A string representing the allocation status
 */
static inline const char * allocated_to_string(char allocated) {
  switch(allocated) {
    case UNALLOCATED: 
      return "false";
    case ALLOCATED:
      return "true";
    case FENCEPOST:
      return "fencepost";
  }
  assert(false);
}

static bool check_color() {
  if (!check_env) {
    // genenv allows accessing environment varibles
    const char * var = getenv(MALLOC_COLOR);
    use_color = var != NULL && !strcmp(var, "1337_CoLoRs");
    check_env = true;
  }
  return use_color;
}

/**
 * @brief Change the tty color based on the block's allocation status
 *
 * @param block The block to print the allocation status of
 */
static void print_color(header * block) {
  if (!check_color()) {
    return;
  }

  switch(get_state(block)) {
    case UNALLOCATED:
      printf("\033[0;32m");
      break;
    case ALLOCATED:
      printf("\033[0;34m");
      break;
    case FENCEPOST:
      printf("\033[0;33m");
      break;
  }
}

static void clear_color() {
  if (check_color()) {
    printf("\033[0;0m");
  }
}

static inline bool is_sentinel(void * p) {
  for (int i = 0; i < N_LISTS; i++) {
    if (&freelistSentinels[i] == p) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Print the free list pointers if RELATIVE_POINTERS is set to true
 * then print the pointers as an offset from the base of the heap. This allows
 * for determinism in testing. 
 * (due to ASLR https://en.wikipedia.org/wiki/Address_space_layout_randomization#Linux)
 *
 * @param p The pointer to print
 */
void print_pointer(void * p) {
  if (is_sentinel(p)) {
    printf("SENTINEL");
  } else {
    if (RELATIVE_POINTERS) {
      printf("%04zd", p - base);
    } else {
      printf("%p", p);
    }
  }
}

/**
 * @brief Verbose printing of all of the metadata fields of each block
 *
 * @param block The block to print
 */
void print_object(header * block) {
  print_color(block);

  printf("[\n");
  printf("\taddr: ");
  print_pointer(block);
  puts("");
  printf("\tsize: %zd\n", get_size(block) );
  printf("\tleft_size: %zd\n", block->left_size);
  printf("\tallocated: %s\n", allocated_to_string(get_state(block)));
  if (!get_state(block)) {
    printf("\tprev: ");
    print_pointer(block->prev);
    puts("");

    printf("\tnext: ");
    print_pointer(block->next);
    puts("");
  }
  printf("]\n");

  clear_color();
}

/**
 * @brief Simple printer that just prints the allocation status of each block
 *
 * @param block The block to print
 */
void print_status(header * block) {
  print_color(block);
  switch(get_state(block)) {
    case UNALLOCATED:
      printf("[U]");
      break;
    case ALLOCATED:
      printf("[A]");
      break;
    case FENCEPOST:
      printf("[F]");
      break;
  }
  clear_color();
}

/*
static void print_bitmap() {
  printf("bitmap: [");
  for(int i = 0; i < N_LISTS; i++) {
    if ((freelist_bitmap[i >> 3] >> (i & 7)) & 1) {
      printf("\033[32m#\033[0m");
    } else {
      printf("\033[34m_\033[0m");
    }
    if (i % 8 == 7) {
      printf(" ");
    }
  }
  puts("]");
}
*/

/**
 * @brief Print a linked list between two nodes using a provided print function
 *
 * @param pf Function to perform the actual printing
 * @param start Node to start printing at
 * @param end Node to stop printing at
 */
void print_sublist(printFormatter pf, header * start, header * end) {  
  for (header * cur = start; cur != end; cur = cur->next) {
    pf(cur); 
  }
}

/**
 * @brief print the full freelist
 *
 * @param pf Function to perform the header printing
 */
void freelist_print(printFormatter pf) {
  if (!pf) {
    return;
  }

  for (size_t i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    if (freelist->next != freelist) {
      printf("L%zu: ", i);
      print_sublist(pf, freelist->next, freelist);
      puts("");
    }
    fflush(stdout);
  }
}

/**
 * @brief print the boundary tags from each chunk from the OS
 *
 * @param pf Function to perform the header printing
 */
void tags_print(printFormatter pf) {
  if (!pf) {
    return;
  }

  for (size_t i = 0; i < numOsChunks; i++) {
    header * chunk = osChunkList[i];
    pf(chunk);
    for (chunk = get_right_header(chunk);
         get_state(chunk) != FENCEPOST; 
         chunk = get_right_header(chunk)) {
        pf(chunk);
    }
    pf(chunk);
    fflush(stdout);
  }
}
