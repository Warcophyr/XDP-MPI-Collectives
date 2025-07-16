#ifndef STDLIB_H
#define STDLIB_H
#include <stdlib.h>
#endif

#ifndef MPI_STRUCT_H
#define MPI_STRUCT_H
typedef struct MPI_process_info {
  int rank;
  int *socket_fd;
} MPI_process_info;

typedef struct mpi_msg_header {
  int src;
  int dest;
  int tag;
  int length;
  MPI_Datatype type;
} mpi_msg_header;

typedef enum MPI_Datatype {
  MPI_CHAR,
  MPI_SIGNED_CHAR,
  MPI_UNSIGNED_CHAR,
  MPI_SHORT,
  MPI_UNSIGNED_SHORT,
  MPI_INT,
  MPI_UNSIGNED,
  MPI_LONG,
  MPI_UNSIGNED_LONG,
  MPI_LONG_LONG,
  MPI_UNSIGNED_LONG_LONG,
  MPI_FLOAT,
  MPI_DOUBLE,
  MPI_LONG_DOUBLE,
  MPI_C_BOOL,
  MPI_WCHAR
} MPI_Datatype;

typedef enum MPI_Tag {
  MPI_ANY_TAG,
  MPI_SEND,
  MPI_BCAST,
  MPI_REDUCE,
  MPI_SCATTER,
  MPI_GATHER,
  MPI_ALL_REDUCE,
  MPI_ALL_GATHER,
  MPI_TAG_UB
} MPI_Tag;

#endif