#ifndef UTIL_H
#define UTIL_H

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;

typedef char util_dummy_t1[1 / (sizeof (uint8_t ) == 1)];
typedef char util_dummy_t2[1 / (sizeof (uint16_t) == 2)];
typedef char util_dummy_t4[1 / (sizeof (uint32_t) == 4)];
typedef char util_dummy_t8[1 / (sizeof (uint64_t) == 8)];

// This stuff should probably be conditional on OS

// OS X needs it this way:
typedef uint32_t size_t;
void		*memset (void *, int , size_t);
void		*memcpy (void *, const void *, size_t);
int		memcmp (const void *, const void *, size_t);

void		exit (int);
int		puts (const char);

#endif
