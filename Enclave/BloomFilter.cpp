#include "BloomFilter.h"
#include "AES.h"
#include "Hash.h"
#include "Enclave.h"

//credited to http://blog.michaelschmatz.com/2016/04/11/how-to-write-a-bloom-filter-cpp/
//https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.h

//https://hur.st/bloomfilter/?n=100000&p=1.0E-6&m=&k=13
//https://drewdevault.com/2016/04/12/How-to-write-a-better-bloom-filter-in-C.html

BloomFilter::BloomFilter(uint64_t size, uint8_t numHashes) {
	this->size = size;
	m_bits.resize(size);
	m_numHashes = numHashes;
}

void BloomFilter::add(const std::string data) {
	auto hashValues = hashInt(data);

	for (int n = 0; n < m_numHashes; n++) {
		m_bits[nthHash(n, hashValues[0], hashValues[1], m_bits.size())] = true;
	}
}

bool BloomFilter::possiblyContains(const std::string data) {
	std::array<uint64_t, 2> hashValues = hashInt(data);

	for (int n = 0; n < m_numHashes; n++) {
		if (!m_bits[nthHash(n, hashValues[0], hashValues[1], m_bits.size())]) {
			return false;
		}
	}

	return true;
}


std::array<uint64_t, 2> BloomFilter::hashInt(const std::string data)
{
	unsigned char tmplabeldel[SHA256_DIGESTLEN] = { 0 };

	uint8_t keyDel[] = "askdnwejesdsjdns";
	compute_hmac_ex(tmplabeldel, keyDel, 16, (const uint8_t *)data.c_str(), data.length());

	array<uint64_t, 2> ans;
	ans[0] = 0;
	ans[1] = 0;

	int temp = SHA256_DIGESTLEN / 2;
	for (int i = 0; i < SHA256_DIGESTLEN; i++) {
		int ind = i / temp;
		ans[ind] = ans[ind] * 10 + (int)tmplabeldel[i];
		ans[ind] %= this->size;
	}
	return ans;
}

inline uint64_t BloomFilter::nthHash(uint8_t n, uint64_t hashA, uint64_t hashB, uint64_t filterSize) {
	return (hashA + n * hashB) % filterSize;
}

std::string BloomFilter::toString(){
    std::string ans = "";
    for(bool x : m_bits){
        ans += x == true ? "1" : "0";
    }
    return ans;
}

void BloomFilter::parse_string(string str){
    for(int i = 0; i < str.length();i++){
        m_bits[i] = str[i] == '1' ? true : false;
    }
}

