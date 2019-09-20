/**
 * (C) Copyright 2012-2019
 * Matthew Mitchell
 * Caleb James DeLisle
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

// This algorithm was shamelessly stolen from cbitcoin CBValidationFunctions.c
// https://github.com/MatthewLM/cbitcoin/blob/6c143252/src/CBValidationFunctions.c

#include <stdbool.h>

// Set the max target to the highest that work can represent
#define CB_MAX_TARGET 0x207FFFFF

int Work_check(const unsigned char * hash, int target) {

	// Get trailing zero bytes
	int zeroBytes = target >> 24;

	// Check target is less than or equal to maximum.
	if (target > CB_MAX_TARGET)
		return false;

	// Modify the target to the mantissa (significand).
	target &= 0x00FFFFFF;

	// Check mantissa is below 0x800000.
	if (target > 0x7FFFFF)
		return false;

	// Fail if hash is above target. First check leading bytes to significant part.
	// As the hash is seen as little-endian, do this backwards.
	for (int x = 0; x < 32 - zeroBytes; x++)
		if (hash[31 - x])
			// A byte leading to the significant part is not zero
			return false;

	// Check significant part
	int significantPart = hash[zeroBytes - 1] << 16;
	significantPart |= hash[zeroBytes - 2] << 8;
	significantPart |= hash[zeroBytes - 3];
	if (significantPart >= target)
		return false;

	return true;

}
