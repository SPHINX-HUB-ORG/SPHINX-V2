#ifndef COTSHORTKEYS_SENDER_IMPL_H___
#define COTSHORTKEYS_SENDER_IMPL_H___

#include "COTSK_impl.h"

#include <cryptoTools/Common/MatrixView.h>
#include "../../install/include/libOTe/libOTe/Tools/Tools.h"

class COTSK_SenderSessionExtendHandler {

    public:
        COTSK_SenderSessionExtendHandler(const shared_ptr<CommParty> & channel, uint32_t L,uint32_t maxExpandBits) :
																		_L(L),
																		_maxExpandBits(maxExpandBits), 
																		_prg_delta(L), 
																		_u(L*maxExpandBits/8) ,
																		_q(L*maxExpandBits/8),
																		_delta(L)
	   {
		    _tdeltai_aligned16 = (byte *) _mm_malloc(L*maxExpandBits/8,16);
			_channel = channel;
        }
	
		void keyPrg(const byte *k, const vector<byte> & delta) {
			uint32_t prgCacheSize = _maxExpandBits/8;
			_delta = delta;
			for (uint32_t i= 0; i < _L; i++) {
				_prg_delta[i].init((byte *)k+16*i,prgCacheSize);
			}
		}
	
       void extend (uint32_t size_bits, byte *q_j_out)
	   {
		   uint32_t mBytes = size_bits/8; 
		   _channel->read(_u.data(),mBytes*_L);
		   for (uint32_t i =0; i < _L; i++) {
			   const byte * tdeltai = expand_tdeltai(i,mBytes);
			   update_qi(mBytes,qi(i,mBytes), ui(i,mBytes), tdeltai, _delta[i]); 
		   }
	   
	   		osuCrypto::MatrixView<osuCrypto::u8> m1(_q.data(), _L ,mBytes);
			osuCrypto::MatrixView<osuCrypto::u8> m2(q_j_out, mBytes*8 ,_L/8);
 			osuCrypto::sse_transpose(m1,m2);
		    
	 }

	
    private:
	
	     byte * ui(uint32_t i, uint32_t mBytes) {return _u.data() + i*mBytes;} 
 	     byte * qi(uint32_t i, uint32_t mBytes) {return _q.data() + i*mBytes;} 
         const byte * expand_tdeltai(uint32_t i, uint32_t mBytes) {return _prg_delta[i].getBytes(_tdeltai_aligned16+i*mBytes, mBytes); }
    
         void update_qi(uint32_t mBytes, byte *qi, const byte * ui, const byte *tdeltai , const byte deltai) {
             for (uint32_t j = 0; j < mBytes; j++) {
                	qi[j] = deltai ? ui[j] ^ tdeltai[j] : tdeltai[j];
	          }
         }
	
         uint32_t _L;
         uint32_t _maxExpandBits;
         shared_ptr<CommParty>  _channel;
		 vector<COTSK_Prg> _prg_delta;
		 vector<byte> _u;
		 vector<byte> _q;
		 vector<byte> _delta;
		 byte *_tdeltai_aligned16;
};

class COTSK_SenderSessionOTHandler {
    public:
        COTSK_SenderSessionOTHandler(OTExtensionBristolReceiver & baseOTReceiver, uint32_t L) : 
                _delta(L+1,0x00),
                _L(L),
				_x_sigma((L+1)*16),
                _baseOTReceiver(baseOTReceiver)
                {}
        
        void initializeOrRekey(const byte *delta) {
            for (uint32_t i=0; i < _L; i++) {
                _delta[i+1] = index(delta,i) ? 0x01 : 0x00;
            }
			OTExtensionGeneralRInput generalRInput(_delta, 128);
            auto output = _baseOTReceiver.transfer(&generalRInput);
			_x_sigma = ((OTOnByteArrayROutput *)output.get() )->getXSigma();

#ifdef DEBUG_PRINT
//			debugPrint((OTOnByteArrayROutput *)output.get());
#endif
        }
		const vector<byte> & getDelta() {return _delta;}
	
        const byte *getKdelta() { 
            return _x_sigma.data() + 16;
		}
	
    private:
	
		void debugPrint(OTOnByteArrayROutput *sigma) {
    	    cout << "Arr 0 : First byte of each key" << endl; 
    		for (uint32_t i= 0; i < _L; i++) {
				byte *b = sigma->getXSigma().data() + (i+1)*16;
				cout <<  hex << (int)b[0] << " " ;
			}
			cout << dec << endl;
		}
	
    private:
        vector<byte> _delta;
        uint32_t _L;
		vector<byte> _x_sigma;
        OTExtensionBristolReceiver & _baseOTReceiver;

  
};

class COTSK_SenderSession {
 
    public:
        COTSK_SenderSession(OTExtensionBristolReceiver & baseOTReceiver,
                            const shared_ptr<CommParty> & channel,
                            uint32_t L,
                            uint32_t maxExpandBits) : _L(L), _maxExpandBits(maxExpandBits),_OThandler(baseOTReceiver,L),_extendHandler(channel,L,maxExpandBits)
		{
			_channel = channel;
		}
    
        void initializeOrRekey(const byte *delta) {
			cerr << "calling handler init.." << endl; 
            _OThandler.initializeOrRekey(delta);
		    _extendHandler.keyPrg(_OThandler.getKdelta(),_OThandler.getDelta());
        }
    
        void extend (uint32_t size_bits, byte *t_j_i_out) {
#ifdef DEBUG_PRINT
//			cout << "Sender extend: size_bits "  << size_bits << endl;
#endif		
			_extendHandler.extend(size_bits,t_j_i_out);
		}
    
    private:
      uint32_t _L;
      uint32_t _maxExpandBits;
      shared_ptr<CommParty> _channel;
      COTSK_SenderSessionOTHandler  _OThandler;
	  COTSK_SenderSessionExtendHandler _extendHandler;
    
};

class COTSK_Sender {
	public:
		COTSK_Sender(const string& serverAddr, int baseOTport, const shared_ptr<CommParty> & channel, uint32_t L, uint8_t numSessions,uint32_t maxExpandBits) 
            : _baseOTReceiver(serverAddr,baseOTport,true,channel) {
       
           _sessions.resize(numSessions);
           for (uint8_t i=0; i < numSessions; i++) {
               _sessions[i] =new COTSK_SenderSession(_baseOTReceiver,channel,L,maxExpandBits);              
   		   }

		}
    
	    void initializeOrRekey(uint8_t sessionId, const byte *delta) {
			cerr << "calling session init.." << endl; 
			_sessions[sessionId]->initializeOrRekey(delta);
        }
    
        void extend (uint8_t sessionId, uint32_t size_bits , byte *q_i_j) {
            _sessions[sessionId]->extend(size_bits, q_i_j);
        }
 	
	private:
        OTExtensionBristolReceiver _baseOTReceiver;
		vector<COTSK_SenderSession *> _sessions;
};





#endif