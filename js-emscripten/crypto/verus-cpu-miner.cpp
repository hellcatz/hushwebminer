// verus-cpu-solver.cpp : Defines the entry point for the console application.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <memory.h>

#include <cstdint>

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <future>
#include <thread>
#include <sstream> 

#define SHA256_DIGEST_SIZE			32

#define ZCASH_SOLUTION_SIZE			1487
#define ZCASH_BLOCK_HEADER_LEN		140
#define ZCASH_NONCE_LEN				32
#define ZCASH_SOLSIZE_LEN			3

#define ZCASH_SOLSIZE_HEX			"fd4005"
#define ZCASH_SOL_LEN				1344 // ((1 << PARAM_K) * (PREFIX + 1) / 8)

#define ZCASH_BLOCK_OFFSET_NTIME    (4 + 3 * 32)
#define ZCASH_BLOCK_OFFSET_NONCE    (108)

#define N_ZERO_BYTES				12

#ifdef SSE_ENABLE

#include "immintrin.h"

#define NUMROUNDS 5

#ifdef _WIN32
typedef unsigned long long u64;
#else
typedef unsigned long u64;
#endif
typedef __m128i u128;

extern u128 rc[40];

#define LOAD(src) _mm_load_si128((u128 *)(src))
#define STORE(dest,src) _mm_storeu_si128((u128 *)(dest),src)

#define AES4_zero(s0, s1, s2, s3, rci) \
  s0 = _mm_aesenc_si128(s0, rc0[rci]); \
  s1 = _mm_aesenc_si128(s1, rc0[rci + 1]); \
  s2 = _mm_aesenc_si128(s2, rc0[rci + 2]); \
  s3 = _mm_aesenc_si128(s3, rc0[rci + 3]); \
  s0 = _mm_aesenc_si128(s0, rc0[rci + 4]); \
  s1 = _mm_aesenc_si128(s1, rc0[rci + 5]); \
  s2 = _mm_aesenc_si128(s2, rc0[rci + 6]); \
  s3 = _mm_aesenc_si128(s3, rc0[rci + 7]); \

#define MIX4(s0, s1, s2, s3) \
  tmp  = _mm_unpacklo_epi32(s0, s1); \
  s0 = _mm_unpackhi_epi32(s0, s1); \
  s1 = _mm_unpacklo_epi32(s2, s3); \
  s2 = _mm_unpackhi_epi32(s2, s3); \
  s3 = _mm_unpacklo_epi32(s0, s2); \
  s0 = _mm_unpackhi_epi32(s0, s2); \
  s2 = _mm_unpackhi_epi32(s1, tmp); \
  s1 = _mm_unpacklo_epi32(s1, tmp);

#define TRUNCSTORE(out, s0, s1, s2, s3) \
  *(u64*)(out) = *(((u64*)&s0 + 1)); \
  *(u64*)(out + 8) = *(((u64*)&s1 + 1)); \
  *(u64*)(out + 16) = *(((u64*)&s2 + 0)); \
  *(u64*)(out + 24) = *(((u64*)&s3 + 0));

void haraka512_zero(unsigned char *out, const unsigned char *in);

#endif


int	verbose = 0;

int32_t	cpu_mode = 1;
int32_t	mining = 0;

void debug(const char *fmt, ...)
{
	va_list     ap;
	if (!verbose)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void warn(const char *fmt, ...)
{
	va_list     ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void fatal(const char *fmt, ...)
{
	va_list     ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

void hexdump(uint8_t *a, uint32_t a_len)
{
	for (int i = 0; i < a_len; i++)
		fprintf(stderr, "%02x", *(a + i));
}

void hexdump_xor(uint8_t *a, uint8_t *b, uint32_t a_len)
{
	for (int i = 0; i < a_len; i++)
		fprintf(stderr, "%02x", (*(a + i)) ^ (*(b + i)));
}

void hexdump_reverse(uint8_t *a, uint32_t a_len)
{
	for (int i = a_len - 1; i >= 0; i--)
		fprintf(stderr, "%02x ", *(a + i));
}

char *s_hexdump(const void *_a, uint32_t a_len)
{
	const uint8_t	*a = (uint8_t*)_a;
	static char		buf[4096];
	uint32_t		i;
	for (i = 0; i < a_len && i + 2 < sizeof(buf); i++)
		sprintf(buf + i * 2, "%02x", a[i]);
	buf[i * 2] = 0;
	return buf;
}

uint8_t hex2val(const char *base, size_t off)
{
	const char          c = base[off];
	if (c >= '0' && c <= '9')           return c - '0';
	else if (c >= 'a' && c <= 'f')      return 10 + c - 'a';
	else if (c >= 'A' && c <= 'F')      return 10 + c - 'A';
	fatal("Invalid hex char at offset %zd: ...%c...\n", off, c);
	return 0;
}

static const unsigned char sbox[256] =
{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#define XT(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))

// Simulate _mm_unpacklo_epi32
void unpacklo32(unsigned char *t, unsigned char *a, unsigned char *b)
{
	unsigned char tmp[16];
	memcpy(tmp, a, 4);
	memcpy(tmp + 4, b, 4);
	memcpy(tmp + 8, a + 4, 4);
	memcpy(tmp + 12, b + 4, 4);
	memcpy(t, tmp, 16);
}

// Simulate _mm_unpackhi_epi32
void unpackhi32(unsigned char *t, unsigned char *a, unsigned char *b)
{
	unsigned char tmp[16];
	memcpy(tmp, a + 8, 4);
	memcpy(tmp + 4, b + 8, 4);
	memcpy(tmp + 8, a + 12, 4);
	memcpy(tmp + 12, b + 12, 4);
	memcpy(t, tmp, 16);
}

// Simulate _mm_aesenc_si128 instructions from AESNI
void aesenc_rc0(unsigned char *s)
{
	unsigned char i, t, u;
	unsigned char v[4][4];

	for (i = 0; i < 16; ++i) {
		v[((i >> 2) + 4 - (i & 3)) & 3][i & 3] = sbox[s[i]];
	}
	for (i = 0; i < 4; ++i) {
		t = v[i][0];
		u = v[i][0] ^ v[i][1] ^ v[i][2] ^ v[i][3];
		v[i][0] = v[i][0] ^ u ^ XT(v[i][0] ^ v[i][1]);
		v[i][1] = v[i][1] ^ u ^ XT(v[i][1] ^ v[i][2]);
		v[i][2] = v[i][2] ^ u ^ XT(v[i][2] ^ v[i][3]);
		v[i][3] = v[i][3] ^ u ^ XT(v[i][3] ^ t);
	}
	for (i = 0; i < 16; ++i) {
		s[i] = (unsigned char)v[i >> 2][i & 3];
	}
}

void haraka512_perm_zero(unsigned char *out, unsigned char *in)
{
	int i, j;
	unsigned char s[64], tmp[16];
	//uchar rk[40][16];

	memcpy(s, in, 64);

#pragma unroll 5
	for (i = 0; i < 5; ++i) {
		// aes round(s)
		for (j = 0; j < 2; ++j) {
			aesenc_rc0(s);
			aesenc_rc0(s + 16);
			aesenc_rc0(s + 32);
			aesenc_rc0(s + 48);
		}
		unpacklo32(tmp, s, s + 16);
		unpackhi32(s, s, s + 16);
		unpacklo32(s + 16, s + 32, s + 48);
		unpackhi32(s + 32, s + 32, s + 48);
		unpacklo32(s + 48, s, s + 32);
		unpackhi32(s, s, s + 32);
		unpackhi32(s + 32, s + 16, tmp);
		unpacklo32(s + 16, s + 16, tmp);
	}

	memcpy(out, s, 64);
}

/* Slower Portable AES */
void haraka512_port_zero(unsigned char *out, unsigned char *in)
{
	int i;
	unsigned char buf[64];

	haraka512_perm_zero(buf, in);

	/* Feed-forward */
	for (i = 0; i < 64; i++) {
		buf[i] = buf[i] ^ in[i];
	}

	/* Truncated */
	memcpy(out, buf + 8, 8);
	memcpy(out + 8, buf + 24, 8);
	memcpy(out + 16, buf + 32, 8);
	memcpy(out + 24, buf + 48, 8);
}

#ifdef SSE_ENABLE
/* CPU Optimized AES */
typedef __m128i u128;
u128 rc0[40] = { 0 };
void haraka512_zero(unsigned char *out, const unsigned char *in) {
	u128 s[4], tmp;

	s[0] = LOAD(in);
	s[1] = LOAD(in + 16);
	s[2] = LOAD(in + 32);
	s[3] = LOAD(in + 48);

	AES4_zero(s[0], s[1], s[2], s[3], 0);
	MIX4(s[0], s[1], s[2], s[3]);

	AES4_zero(s[0], s[1], s[2], s[3], 8);
	MIX4(s[0], s[1], s[2], s[3]);

	AES4_zero(s[0], s[1], s[2], s[3], 16);
	MIX4(s[0], s[1], s[2], s[3]);

	AES4_zero(s[0], s[1], s[2], s[3], 24);
	MIX4(s[0], s[1], s[2], s[3]);

	AES4_zero(s[0], s[1], s[2], s[3], 32);
	MIX4(s[0], s[1], s[2], s[3]);

	s[0] = _mm_xor_si128(s[0], LOAD(in));
	s[1] = _mm_xor_si128(s[1], LOAD(in + 16));
	s[2] = _mm_xor_si128(s[2], LOAD(in + 32));
	s[3] = _mm_xor_si128(s[3], LOAD(in + 48));

	TRUNCSTORE(out, s[0], s[1], s[2], s[3]);
}
#endif

bool full_target_test(const unsigned char *hash, const unsigned char *target)
{
#pragma unroll 32
	for (int i = 0; i < 32; i++) {
		if (hash[31 - i] < target[31 - i]) {
			return true;
		}
		else if (hash[31 - i] == target[31 - i]) {
			continue;
		}
		else {
			return false;
		}
	}

	// target equal hash
	return true;
}

uint32_t print_solver_line(uint32_t value, uint8_t *header, size_t fixed_nonce_bytes, uint8_t *target, char *job_id)
{
	uint8_t	*p;
	uint8_t	buffer[ZCASH_SOLUTION_SIZE];
	memset(buffer, 0, ZCASH_SOLUTION_SIZE);
	memcpy(buffer, header, ZCASH_BLOCK_HEADER_LEN);
	memcpy(buffer + ZCASH_BLOCK_HEADER_LEN, "\xfd\x40\x05", ZCASH_SOLSIZE_LEN);
	printf("sol: %s ", job_id);// job id
	p = header + ZCASH_BLOCK_OFFSET_NTIME;
	printf("%02x%02x%02x%02x ", p[0], p[1], p[2], p[3]); // ntime
	printf("%s ", s_hexdump(header + ZCASH_BLOCK_HEADER_LEN - ZCASH_NONCE_LEN + fixed_nonce_bytes, ZCASH_NONCE_LEN - fixed_nonce_bytes)); // header
	memcpy(buffer + ZCASH_BLOCK_HEADER_LEN + ZCASH_SOLSIZE_LEN + ZCASH_SOL_LEN - 15, &value, 4);
	printf("%s%s\n", ZCASH_SOLSIZE_HEX, s_hexdump(buffer + ZCASH_BLOCK_HEADER_LEN + ZCASH_SOLSIZE_LEN, ZCASH_SOL_LEN)); // solution
	fflush(stdout);
	return true;
}

size_t solve_verushash(size_t global_ws,
	uint8_t *header, size_t header_len,
	uint8_t *target, char *job_id,
	uint32_t *shares, size_t fixed_nonce_bytes,
	uint32_t offset)
{
	uint8_t		vout_hash[64], pinput[64];

	unsigned char block_41970[] = { 0xfd, 0x40, 0x05 };

	int len = ZCASH_SOLUTION_SIZE;
	unsigned char full_buf[ZCASH_SOLUTION_SIZE];

	uint32_t cpu_shares = 0;

	unsigned char buf[128];
	unsigned char *bufPtr = buf;
	int i = 0, j = 0, pos = 0, nextOffset = 64;
	unsigned char *bufPtr2 = bufPtr + nextOffset;
	unsigned char *ptr = (unsigned char *)full_buf;

	auto start = std::chrono::system_clock::now();

	memset(full_buf, 0, ZCASH_SOLUTION_SIZE);
	memcpy(full_buf, header, header_len);
	memcpy(full_buf + header_len, block_41970, 3);

	memset(buf, 0, 128);

	// digest up to 32 bytes at a time
	for (pos = 0; pos < len; pos += 32)
	{
		if (len - pos >= 32)
		{
			memcpy(bufPtr + 32, ptr + pos, 32);
#ifdef SSE_ENABLE
                        haraka512_zero(bufPtr2, bufPtr);
#else
			haraka512_port_zero(bufPtr2, bufPtr);
#endif
			bufPtr2 = bufPtr;
			bufPtr += nextOffset;
			nextOffset *= -1;
			continue;
		}

		i = (int)(len - pos);
		memcpy(bufPtr + 32, ptr + pos, i);
		memset(bufPtr + 32 + i, 0, 32 - i);
		break;
	}

	memcpy(pinput, bufPtr, 64);

	for (i = 0; i < global_ws; i++)
	{
		// next solution
		*((uint32_t *)(pinput + 32)) = (uint32_t)(i + offset);
		// get hash result
#ifdef SSE_ENABLE
                        haraka512_zero(vout_hash, pinput);
#else
                        haraka512_port_zero(vout_hash, pinput);
#endif
		// test against target
		if (full_target_test(vout_hash, target) == true) {
			*shares += 1;
			print_solver_line((uint32_t)(i + offset), header, fixed_nonce_bytes, target, job_id);
		}
	}

	if (verbose)
	{
		auto end = std::chrono::system_clock::now();
		auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
		double seconds = (double)microseconds.count() / 1000000.0;
		debug("hashrate: %f MH/s\n", (double)(global_ws / seconds) / 1000000.0);
	}

	return global_ws;
}

static std::string background_read_next_line_stdin()
{
	std::string answer;
	std::getline(std::cin, answer, '\n');
	return answer;
}

void mining_parse_job(char *str, uint8_t *target, size_t target_len,
	char *job_id, size_t job_id_len, uint8_t *header, size_t header_len,
	size_t *fixed_nonce_bytes)
{
	uint32_t		str_i, i;
	// parse target
	str_i = 0;
	for (i = 0; i < target_len; i++, str_i += 2)
		target[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
	assert(str[str_i] == ' ');
	str_i++;
	// parse job_id
	for (i = 0; i < job_id_len && str[str_i] != ' '; i++, str_i++)
		job_id[i] = str[str_i];
	assert(str[str_i] == ' ');
	assert(i < job_id_len);
	job_id[i] = 0;
	str_i++;
	// parse header and nonce_leftpart
	for (i = 0; i < header_len && str[str_i] != ' '; i++, str_i += 2)
		header[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
	assert(str[str_i] == ' ');
	str_i++;
	*fixed_nonce_bytes = 0;
	while (i < header_len && str[str_i])
	{
		header[i] = hex2val(str, str_i) * 16 + hex2val(str, str_i + 1);
		i++;
		str_i += 2;
		(*fixed_nonce_bytes)++;
	}
	assert(!str[str_i]);
	memset(header + header_len - N_ZERO_BYTES, 0, N_ZERO_BYTES);
}

void run_miner(uint8_t *header, size_t header_len, size_t global_ws)
{
	char		line_input[4096];
	uint8_t		target[32];
	char		job_id[256];
	size_t		fixed_nonce_bytes = 0;

	uint64_t		i = 0xffffffffffffffff;
	uint64_t		total = 0;
	uint32_t		shares = 0, offset = 0;;
	uint64_t		total_shares = 0;
	uint64_t		total_hashes = 0;
	uint64_t		t0 = 0, t1;
	uint64_t		status_period = 500e3; // time (usec) between statuses

	std::string line = "";
	std::future<std::string> future;

	auto start = std::chrono::system_clock::now();
	auto end = std::chrono::system_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

	memset(job_id, 0, 256);
	memset(target, 0, 32);
	target[31] = 0;

	future = std::async(background_read_next_line_stdin);

	bool runLoop = true;

	while (runLoop == true)
	{
		// read incoming lines (mining jobs)
		if (future.wait_for(std::chrono::microseconds(0)) == std::future_status::ready)
		{
			line = future.get();
			future = std::async(background_read_next_line_stdin);
			if (line.length() > 0) {
				memcpy(line_input, line.c_str(), line.length());
				line_input[line.length()] = 0;
				line = "";

				mining_parse_job(line_input,
					target, sizeof(target),
					job_id, sizeof(job_id),
					header, ZCASH_BLOCK_HEADER_LEN,
					&fixed_nonce_bytes);

				// unique per gpu/cpu
				header[ZCASH_BLOCK_OFFSET_NONCE + 22] = (uint8_t)(cpu_mode % 255);
			}
		}

		// increment nonce once possible solutions exhausted
		offset = (total_hashes % ((0xffffffff - global_ws) + 1));
		if (offset == 0 || offset < global_ws) {
			i++;
			*((uint64_t *)&header[ZCASH_BLOCK_OFFSET_NONCE + 23]) = i;
		}

		shares = 0;
		total_hashes += solve_verushash(global_ws, header, header_len, target, job_id, &shares, fixed_nonce_bytes, offset);
		total_shares += shares;

		// report status updates
		end = std::chrono::system_clock::now();
		ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		if (ms.count()>999) {
			start = end;
			printf("status: %llu %lu\n", (total_hashes / 1000000llu), total_shares);
			fflush(stdout);
		}
	}

	//future._Abandon();
}

std::string read_file(const char* file)
{
	std::ifstream t(file);
	std::string str;

	t.seekg(0, std::ios::end);
	str.reserve(t.tellg());
	t.seekg(0, std::ios::beg);

	str.assign((std::istreambuf_iterator<char>(t)),
		std::istreambuf_iterator<char>());

	return str;
}

void usage(const char *progname)
{
	printf("Usage: %s [options]\n"
		"A standalone VerusHash solver.\n"
		"\n"
		"Options are:\n"
		"  -h, --help         display this help and exit\n"
		"  --cpu <id>         use CPU thread <id> (default: 0)\n"
		"  --sse              Use CPU optimized AES encryption if available"
		, progname);
}

uint32_t parse_num(char *str)
{
	char	*endptr;
	uint32_t	n;
	n = strtoul(str, &endptr, 0);
	if (endptr == str || *endptr)
		fatal("'%s' is not a valid number\n", str);
	return n;
}

int main(int argc, char **argv)
{
	size_t		global_ws = 1000000;

	uint32_t header_len = ZCASH_BLOCK_HEADER_LEN;
	uint8_t  header[ZCASH_BLOCK_HEADER_LEN] = { 0, };

	std::string temp;
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if ((arg == "-h") || (arg == "--help")) {
			usage(argv[0]);
			return 0;
		}
		else if ((arg == "-c") || (arg == "--cpu")) {
			if (i + 1 < argc) {
				i++;
				cpu_mode = parse_num(argv[i++]);
			}
		}
		else if ((arg == "-v") || (arg == "--verbose")) {
			verbose = 1;
		}
	}

	fprintf(stdout, "VERUSARMY mining mode ready\n");
	fflush(stdout);

	run_miner(header, header_len, global_ws);
	return 0;
}
