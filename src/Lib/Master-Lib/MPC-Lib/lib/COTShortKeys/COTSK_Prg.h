#include <cstdlib>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <emmintrin.h>

class COTSK_Prg {
	
	public:
	
		COTSK_Prg() {}
		
		void init(const byte *key128bit , uint32_t maxBytes) {
			
			assert (maxBytes % 16 == 0);
			_ctr_inc = 1;
			_buff = (byte *)_mm_malloc(maxBytes,16);
			_ctr = (byte *)_mm_malloc(maxBytes,16);
			_ctr_u64 = (uint64_t *) _ctr;
			memcpy(_key,key128bit,16);
			
	        _aes = new EVP_CIPHER_CTX();
       		EVP_CIPHER_CTX_init(_aes);
        	EVP_EncryptInit(_aes, EVP_aes_128_ecb(),_key, (byte *)&_iv);
			
		}

		void randomInit( uint32_t maxBytes) {
		
			byte randKey[16];
			auto r = rand();
			for (uint32_t i=0; i < 16; i++) {
				randKey[i] = (byte) (i + r);
			}
			init(randKey,maxBytes);
		}

		const byte *getBytes( uint32_t sizeBytes) {
			return getBytes (nullptr,sizeBytes);
		}
	
		const byte *getBytes( byte *client_buff, uint32_t sizeBytes) {
			for (uint32_t i = 0; i < sizeBytes/16; i++) {
				_ctr_u64[2*i] = (++_ctr_inc);
			}
			
		   int tmp;
		   byte *use_buff = (client_buff != nullptr) ? client_buff : _buff;
	       int rc = EVP_EncryptUpdate(_aes, use_buff, &tmp, _ctr, sizeBytes);
		   assert (rc == 1);
			
			return use_buff;
		}	
	
	private:
		byte *      _buff = nullptr;
		byte *      _ctr = nullptr;
		uint64_t *  _ctr_u64 = nullptr;
		byte        _key[16];
		uint64_t    _ctr_inc;
		EVP_CIPHER_CTX *_aes = nullptr;
		__m128i _iv = _mm_setzero_si128();

};
