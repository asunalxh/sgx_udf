#pragma once
#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <vector>
#include <array>
using namespace std;

class BloomFilter {
public:
	BloomFilter(uint64_t size, uint8_t numHashes);

	void add(const std::string data);
	bool possiblyContains(const std::string data);

	std::string toString();
	void parse_string(std::string str);

private:
	uint64_t size;
	uint8_t m_numHashes;
	std::vector<bool> m_bits;

	std::array<uint64_t, 2> hashInt(const std::string data);
	uint64_t nthHash(uint8_t n, uint64_t hashA, uint64_t hashB, uint64_t filterSize);
};
#endif;

