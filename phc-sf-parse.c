/*
 * Example code for a decoder and encoder of "hash strings", with Argon2i
 * parameters.
 *
 * This code comprises three sections:
 *
 *   -- The first section contains generic Base64 encoding and decoding
 *   functions. It is conceptually applicable to any hash function
 *   implementation that uses Base64 to encode and decode parameters,
 *   salts and outputs. It could be made into a library, provided that
 *   the relevant functions are made public (non-static) and be given
 *   reasonable names to avoid collisions with other functions.
 *
 *   -- The second section is specific to Argon2i. It encodes and decodes
 *   the parameters, salts and outputs. It does not compute the hash
 *   itself.
 *
 *   -- The third section is test code, with a main() function. With
 *   this section, the whole file compiles as a stand-alone program
 *   that exercises the encoding and decoding functions with some
 *   test vectors.
 *
 * The code was originally written by Thomas Pornin <pornin@bolet.org>,
 * to whom comments and remarks may be sent. It is released under what
 * should amount to Public Domain or its closest equivalent; the
 * following mantra is supposed to incarnate that fact with all the
 * proper legal rituals:
 *
 * ---------------------------------------------------------------------
 * This file is provided under the terms of Creative Commons CC0 1.0
 * Public Domain Dedication. To the extent possible under law, the
 * author (Thomas Pornin) has waived all copyright and related or
 * neighboring rights to this file. This work is published from: Canada.
 * ---------------------------------------------------------------------
 *
 * Copyright (c) 2015 Thomas Pornin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* ==================================================================== */
/*
 * Common code; could be shared between different hash functions.
 *
 * Note: the Base64 functions below assume that uppercase letters (resp.
 * lowercase letters) have consecutive numerical codes, that fit on 8
 * bits. All modern systems use ASCII-compatible charsets, where these
 * properties are true. If you are stuck with a dinosaur of a system
 * that still defaults to EBCDIC then you already have much bigger
 * interoperability issues to deal with.
 */

/*
 * Some macros for constant-time comparisons. These work over values in
 * the 0..255 range. Returned value is 0x00 on "false", 0xFF on "true".
 */
#define EQ(x, y)   ((((-((unsigned)(x) ^ (unsigned)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y)   ((((unsigned)(y) - (unsigned)(x)) >> 8) & 0xFF)
#define GE(x, y)   (GT(y, x) ^ 0xFF)
#define LT(x, y)   GT(y, x)
#define LE(x, y)   GE(y, x)

/*
 * Convert value x (0..63) to corresponding Base64 character.
 */
static int
b64_byte_to_char(unsigned x)
{
	return (LT(x, 26) & (x + 'A'))
		| (GE(x, 26) & LT(x, 52) & (x + ('a' - 26)))
		| (GE(x, 52) & LT(x, 62) & (x + ('0' - 52)))
		| (EQ(x, 62) & '+') | (EQ(x, 63) & '/');
}

/*
 * Convert character c to the corresponding 6-bit value. If character c
 * is not a Base64 character, then 0xFF (255) is returned.
 */
static unsigned
b64_char_to_byte(int c)
{
	unsigned x;

	x = (GE(c, 'A') & LE(c, 'Z') & (c - 'A'))
		| (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26)))
		| (GE(c, '0') & LE(c, '9') & (c - ('0' - 52)))
		| (EQ(c, '+') & 62) | (EQ(c, '/') & 63);
	return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

/*
 * Convert some bytes to Base64. 'dst_len' is the length (in characters)
 * of the output buffer 'dst'; if that buffer is not large enough to
 * receive the result (including the terminating 0), then (size_t)-1
 * is returned. Otherwise, the zero-terminated Base64 string is written
 * in the buffer, and the output length (counted WITHOUT the terminating
 * zero) is returned.
 */
static size_t
to_base64(char *dst, size_t dst_len, const void *src, size_t src_len)
{
	size_t olen;
	const unsigned char *buf;
	unsigned acc, acc_len;

	olen = (src_len / 3) << 2;
	switch (src_len % 3) {
	case 2:
		olen ++;
		/* fall through */
	case 1:
		olen += 2;
		break;
	}
	if (dst_len <= olen) {
		return (size_t)-1;
	}
	acc = 0;
	acc_len = 0;
	buf = (const unsigned char *)src;
	while (src_len -- > 0) {
		acc = (acc << 8) + (*buf ++);
		acc_len += 8;
		while (acc_len >= 6) {
			acc_len -= 6;
			*dst ++ = b64_byte_to_char((acc >> acc_len) & 0x3F);
		}
	}
	if (acc_len > 0) {
		*dst ++ = b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
	}
	*dst ++ = 0;
	return olen;
}

/*
 * Decode Base64 chars into bytes. The '*dst_len' value must initially
 * contain the length of the output buffer '*dst'; when the decoding
 * ends, the actual number of decoded bytes is written back in
 * '*dst_len'.
 *
 * Decoding stops when a non-Base64 character is encountered, or when
 * the output buffer capacity is exceeded. If an error occurred (output
 * buffer is too small, invalid last characters leading to unprocessed
 * buffered bits), then NULL is returned; otherwise, the returned value
 * points to the first non-Base64 character in the source stream, which
 * may be the terminating zero.
 */
static const char *
from_base64(void *dst, size_t *dst_len, const char *src)
{
	size_t len;
	unsigned char *buf;
	unsigned acc, acc_len;

	buf = (unsigned char *)dst;
	len = 0;
	acc = 0;
	acc_len = 0;
	for (;;) {
		unsigned d;

		d = b64_char_to_byte(*src);
		if (d == 0xFF) {
			break;
		}
		src ++;
		acc = (acc << 6) + d;
		acc_len += 6;
		if (acc_len >= 8) {
			acc_len -= 8;
			if ((len ++) >= *dst_len) {
				return NULL;
			}
			*buf ++ = (acc >> acc_len) & 0xFF;
		}
	}

	/*
	 * If the input length is equal to 1 modulo 4 (which is
	 * invalid), then there will remain 6 unprocessed bits;
	 * otherwise, only 0, 2 or 4 bits are buffered. The buffered
	 * bits must also all be zero.
	 */
	if (acc_len > 4 || (acc & (((unsigned)1 << acc_len) - 1)) != 0) {
		return NULL;
	}
	*dst_len = len;
	return src;
}

/*
 * Decode decimal integer from 'str'; the value is written in '*v'.
 * Returned value is a pointer to the next non-decimal character in the
 * string. If there is no digit at all, or the value encoding is not
 * minimal (extra leading zeros), or the value does not fit in an
 * 'unsigned long', then NULL is returned.
 */
static const char *
decode_decimal(const char *str, unsigned long *v)
{
	const char *orig;
	unsigned long acc;

	orig = str;
	acc = 0;
	for (orig = str;; str ++) {
		int c;

		c = *str;
		if (c < '0' || c > '9') {
			break;
		}
		c -= '0';
		if (acc > (ULONG_MAX / 10)) {
			return NULL;
		}
		acc *= 10;
		if ((unsigned long)c > (ULONG_MAX - acc)) {
			return NULL;
		}
		acc += (unsigned long)c;
	}
	if (str == orig || (*orig == '0' && str != (orig + 1))) {
		return NULL;
	}
	*v = acc;
	return str;
}

/* ==================================================================== */
/*
 * Code specific to Argon2i.
 *
 * The code below applies the following format:
 *
 *  $argon2i$m=<num>,t=<num>,p=<num>[,keyid=<bin>][,data=<bin>][$<bin>[$<bin>]]
 *
 * where <num> is a decimal integer (positive, fits in an 'unsigned long')
 * and <bin> is Base64-encoded data (no '=' padding characters, no newline
 * or whitespace). The "keyid" is a binary identifier for a key (up to 8
 * bytes); "data" is associated data (up to 32 bytes). When the 'keyid'
 * (resp. the 'data') is empty, then it is ommitted from the output.
 *
 * The last two binary chunks (encoded in Base64) are, in that order,
 * the salt and the output. Both are optional, but you cannot have an
 * output without a salt. The binary salt length is between 8 and 48 bytes.
 * The output length is always exactly 32 bytes.
 */

/*
 * A structure containg the values that get encoded into Argon2i hash
 * strings.
 *
 * key_id_len is 0 if the string contains no key ID.
 * associated_data_len is 0 if the string contains no associated data.
 * salt_len is 0 if the string contains no salt (parameter-only string).
 * output_len is 0 if the string contains no output (a salt string, with
 * parameters and salt but no output).
 */
typedef struct {
	unsigned long m;
	unsigned long t;
	unsigned long p;
	unsigned char key_id[8];
	size_t key_id_len;
	unsigned char associated_data[32];
	size_t associated_data_len;
	unsigned char salt[48];
	size_t salt_len;
	unsigned char output[64];
	size_t output_len;
} argon2i_params;

/*
 * Decode an Argon2i hash string into the provided structure 'pp'.
 * Returned value is 1 on success, 0 on error.
 */
int
argon2i_decode_string(argon2i_params *pp, const char *str)
{
#define CC(prefix)   do { \
		size_t cc_len = strlen(prefix); \
		if (strncmp(str, prefix, cc_len) != 0) { \
			return 0; \
		} \
		str += cc_len; \
	} while (0)

#define CC_opt(prefix, code)   do { \
		size_t cc_len = strlen(prefix); \
		if (strncmp(str, prefix, cc_len) == 0) { \
			str += cc_len; \
			{ code; } \
		} \
	} while (0)

#define DECIMAL(x)   do { \
		unsigned long dec_x; \
		str = decode_decimal(str, &dec_x); \
		if (str == NULL) { \
			return 0; \
		} \
		(x) = dec_x; \
	} while (0)

#define BIN(buf, max_len, len)   do { \
		size_t bin_len = (max_len); \
		str = from_base64(buf, &bin_len, str); \
		if (str == NULL) { \
			return 0; \
		} \
		(len) = bin_len; \
	} while (0)

	pp->key_id_len = 0;
	pp->associated_data_len = 0;
	pp->salt_len = 0;
	pp->output_len = 0;
	CC("$argon2i");
	CC("$m=");
	DECIMAL(pp->m);
	CC(",t=");
	DECIMAL(pp->t);
	CC(",p=");
	DECIMAL(pp->p);

	/*
	 * Both m and t must be no more than 2^32-1. The tests below
	 * use a shift by 30 bits to avoid a direct comparison with
	 * 0xFFFFFFFF, which may trigger a spurious compiler warning
	 * on machines where 'unsigned long' is a 32-bit type.
	 */
	if (pp->m < 1 || (pp->m >> 30) > 3) {
		return 0;
	}
	if (pp->t < 1 || (pp->t >> 30) > 3) {
		return 0;
	}

	/*
	 * The parallelism p must be between 1 and 255. The memory cost
	 * parameter, expressed in kilobytes, must be at least 8 times
	 * the value of p.
	 */
	if (pp->p < 1 || pp->p > 255) {
		return 0;
	}
	if (pp->m < (pp->p << 3)) {
		return 0;
	}

	CC_opt(",keyid=", BIN(pp->key_id, sizeof pp->key_id, pp->key_id_len));
	CC_opt(",data=", BIN(pp->associated_data, sizeof pp->associated_data,
		pp->associated_data_len));
	if (*str == 0) {
		return 1;
	}
	CC("$");
	BIN(pp->salt, sizeof pp->salt, pp->salt_len);
	if (pp->salt_len < 8) {
		return 0;
	}
	if (*str == 0) {
		return 1;
	}
	CC("$");
	BIN(pp->output, sizeof pp->output, pp->output_len);
	if (pp->output_len < 12) {
		return 0;
	}
	return *str == 0;

#undef CC
#undef CC_opt
#undef DECIMAL
#undef BIN
}

/*
 * Encode an Argon2i hash string into the provided buffer. 'dst_len'
 * contains the size, in characters, of the 'dst' buffer; if 'dst_len'
 * is less than the number of required characters (including the
 * terminating 0), then this function returns 0.
 *
 * If pp->output_len is 0, then the hash string will be a salt string
 * (no output). If pp->salt_len is also 0, then the string will be a
 * parameter-only string (no salt and no output).
 *
 * On success, 1 is returned.
 */
int
argon2i_encode_string(char *dst, size_t dst_len, const argon2i_params *pp)
{
#define SS(str)   do { \
		size_t pp_len = strlen(str); \
		if (pp_len >= dst_len) { \
			return 0; \
		} \
		memcpy(dst, str, pp_len + 1); \
		dst += pp_len; \
		dst_len -= pp_len; \
	} while (0)

#define SX(x)   do { \
		char tmp[30]; \
		sprintf(tmp, "%lu", (unsigned long)(x)); \
		SS(tmp); \
	} while (0); \

#define SB(buf, len)   do { \
		size_t sb_len = to_base64(dst, dst_len, buf, len); \
		if (sb_len == (size_t)-1) { \
			return 0; \
		} \
		dst += sb_len; \
		dst_len -= sb_len; \
	} while (0); \

	SS("$argon2i$m=");
	SX(pp->m);
	SS(",t=");
	SX(pp->t);
	SS(",p=");
	SX(pp->p);
	if (pp->key_id_len > 0) {
		SS(",keyid=");
		SB(pp->key_id, pp->key_id_len);
	}
	if (pp->associated_data_len > 0) {
		SS(",data=");
		SB(pp->associated_data, pp->associated_data_len);
	}
	if (pp->salt_len == 0) {
		return 1;
	}
	SS("$");
	SB(pp->salt, pp->salt_len);
	if (pp->output_len == 0) {
		return 1;
	}
	SS("$");
	SB(pp->output, pp->output_len);
	return 1;

#undef SS
#undef SX
#undef SB
}

/* ==================================================================== */
/*
 * Test code.
 */

static const char *KAT_GOOD[] = {
	"$argon2i$m=120,t=5000,p=2",
	"$argon2i$m=120,t=4294967295,p=2",
	"$argon2i$m=2040,t=5000,p=255",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQ",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQA",
	"$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
	"$argon2i$m=120,t=5000,p=2$/LtFjH5rVL8",
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2$BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$EkCWX6pSTqWruiR0",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g",
	NULL
};

static const char *KAT_BAD[] = {
	/* bad function name */
	"$argon2j$m=120,t=5000,p=2",

	/* missing parameter 'm' */
	"$argon2i$t=5000,p=2",

	/* missing parameter 't' */
	"$argon2i$m=120,p=2",

	/* missing parameter 'p' */
	"$argon2i$m=120,t=5000",

	/* value of 'm' is too small (lower than 8*p) */
	"$argon2i$m=15,t=5000,p=2",

	/* value of 't' is invalid */
	"$argon2i$m=120,t=0,p=2",

	/* value of 'p' is invalid (too small) */
	"$argon2i$m=120,t=5000,p=0",

	/* value of 'p' is invalid (too large) */
	"$argon2i$m=2000,t=5000,p=256",

	/* value of 'm' has non-minimal encoding */
	"$argon2i$m=0120,t=5000,p=2",

	/* value of 't' has non-minimal encoding */
	"$argon2i$m=120,t=05000,p=2",

	/* value of 'p' has non-minimal encoding */
	"$argon2i$m=120,t=5000,p=02",

	/* value of 't' exceeds 2^32-1 */
	"$argon2i$m=120,t=4294967296,p=2",

	/* invalid Base64 for keyid (length = 9 characters) */
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0Z",

	/* invalid Base64 for keyid (unprocessed bits are not 0) */
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZR",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQB",

	/* invalid keyid (too large) */
	"$argon2i$m=120,t=5000,p=2,keyid=Mwmcv5/avkXJ",

	/* invalid associated data (too large) */
	"$argon2i$m=120,t=5000,p=2,data=Vrai0ME0m7lorfxfOCG3+6we5N89+2hXwkbv0C5SECab",

	/* invalid salt (too small) */
	"$argon2i$m=120,t=5000,p=2$+yPbRi6hdw",

	/* invalid salt (too large) */
	"$argon2i$m=120,t=5000,p=2$SIZzzPhYC/CXOf64vWG/IZjO/amlRgvKscaRCYwdg9R1boFN/NjaC1VdXdcOtFx+0A",

	/* invalid output (too small) */
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iHSDPHzUhPzK7rCcJgOFfg$c+jbgTK0PT0eCMI",

	/* invalid output (too large) */
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iHSDPHzUhPzK7rCcJgOFfg$KtTPhiUlDb98psIiNxUSZ8GYVEm1CsfEaLJrppBe5poD2/sQOUu5mmowSiQUbH+ZK3PjFdY3KUuf83bT5XqTZy0",

	NULL
};

int
main(void)
{
	const char **s;

	for (s = KAT_GOOD; *s; s ++) {
		const char *str;
		argon2i_params pp;
		char tmp[300];
		size_t len;

		str = *s;
		if (!argon2i_decode_string(&pp, str)) {
			fprintf(stderr, "Failed to decode: %s\n", str);
			exit(EXIT_FAILURE);
		}
		if (!argon2i_encode_string(tmp, sizeof tmp, &pp)) {
			fprintf(stderr, "Failed to encode back: %s\n", str);
			exit(EXIT_FAILURE);
		}
		if (strcmp(str, tmp) != 0) {
			fprintf(stderr, "Decode/encode difference:\n");
			fprintf(stderr, "  in:  %s\n", str);
			fprintf(stderr, "  out: %s\n", tmp);
		}
		len = strlen(str);
		if (!argon2i_encode_string(tmp, len + 1, &pp)) {
			fprintf(stderr, "Encode failure (1): %s\n", str);
			exit(EXIT_FAILURE);
		}
		if (argon2i_encode_string(tmp, len, &pp)) {
			fprintf(stderr, "Encode failure (2): %s\n", str);
			exit(EXIT_FAILURE);
		}
	}

	for (s = KAT_BAD; *s; s ++) {
		const char *str;
		argon2i_params pp;

		str = *s;
		if (argon2i_decode_string(&pp, str)) {
			fprintf(stderr, "Decoded invalid string: %s\n", str);
			exit(EXIT_FAILURE);
		}
	}

	printf("All tests OK\n");
	return 0;
}
