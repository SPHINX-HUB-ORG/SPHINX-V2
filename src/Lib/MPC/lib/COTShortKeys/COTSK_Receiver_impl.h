#ifndef COTSHORTKEYS_RECEIVER_IMPL_H___
#define COTSHORTKEYS_RECEIVER_IMPL_H___

#include "COTSK_impl.h"

class COTSK_ReceiverSessionExtendHandler {

    public:
        COTSK_ReceiverSessionExtendHandler(const shared_ptr<CommParty> & channel, uint32_t L,uint32_t maxExpandBits) : _L(L), _maxExpandBits(maxExpandBits) , _prg_k0(L), _prg_k1(L), _u(L*maxExpandBits/8) {
            _channel = channel;
            _t1_bytes_aligned = (byte *) _mm_malloc(L*maxExpandBits/8,16);
        }
            
    
   		void keyPrg(const byte *k0, const byte *k1) {
    		for (uint32_t i= 0; i < _L; i++) {
				_prg_k0[i].init((byte *)k0+16*i,_maxExpandBits/8);
     			_prg_k1[i].init((byte *)k1+16*i,_maxExpandBits/8);
			}
		 }
       void extend(uint32_t size_bits,  const byte *x_and_r, byte *t_j_i_out) {

		    uint32_t mBytes = size_bits / 8;
            for (uint32_t i=0; i < _L; i++) {
				const byte *t0i = expand_t0i(i, mBytes, t_j_i_out + i*mBytes); 
				const byte *t1i = expand_t1i(i, mBytes);
		        update_ui(mBytes, ui(i,mBytes), t0i, t1i ,x_and_r);
			}

		   _channel->write(_u.data(),mBytes*_L);
	   }
          
    private:
    
         byte * ui(uint32_t i, uint32_t mBytes) {
             return _u.data() + i*mBytes;
         } 
         const byte * expand_t0i(uint32_t i, uint32_t mBytes, byte *out) {
             return _prg_k0[i].getBytes(out,mBytes);
         }
         const byte * expand_t1i(uint32_t i, uint32_t mBytes) {
             return _prg_k1[i].getBytes(_t1_bytes_aligned ,mBytes); 
         }
    
         void update_ui(uint32_t mBytes, byte *ui, const byte * t0i, const byte *t1i , const byte *x) {
             for (uint32_t j = 0; j < mBytes; j++) {
                 ui[j] = t0i[j] ^ t1i[j] ^ x[j];
             }
         }
        
         uint32_t _L;
         uint32_t _maxExpandBits;
         shared_ptr<CommParty>  _channel;
	     vector<COTSK_Prg> _prg_k0;
		 vector<COTSK_Prg> _prg_k1;
         vector<byte> _u;
         byte *_t1_bytes_aligned; 
};



class COTSK_ReceiverSessionOTHandler {
    public:
        COTSK_ReceiverSessionOTHandler(OTExtensionBristolSender & baseOTSender,uint32_t L) : 
                _L(L),
                _x0Arr((L+1)*16),
                _x1Arr((L+1)*16),
                _baseOTSender(baseOTSender) {
 		            _prg.randomInit(16*1024 );
       }

        void initializeOrRekey() {
            
           	this->_prg.getBytes(_x0Arr.data(),_x0Arr.size());
	        this->_prg.getBytes(_x1Arr.data(),_x1Arr.size());
			OTExtensionGeneralSInput generalSInput(_x0Arr,_x1Arr,_L+1);
           	auto output = _baseOTSender.transfer(&generalSInput);
#ifdef DEBUG_PRINT
//            debugPrint(generalSInput);
#endif
        }
        const byte *getK0() { 
            return _x0Arr.data() + 16;
        }
        const byte *getK1() {
            return _x0Arr.data() + 16;
        }   
    private: 

        void debugPrint(OTExtensionGeneralSInput & input) {
                cout << "Arr 0 : First byte of each key" << endl; 
                for (uint32_t i= 0; i < _L - 1; i++) {
                    cout << hex << (int)(input.getX0Arr().data() + (i+1)*16)[0] << " ";		
                }	
                cout << endl;

                cout << "Arr 1 : First byte of each key" << endl; 
                for (uint32_t i= 0; i < _L - 1; i++) {
                    cout << hex << (int)(input.getX1Arr().data() + (i+1)*16)[0] << " ";		
                }	
               cout << endl;
         }
    private:
        uint32_t _L;
        vector<byte> _x0Arr;
        vector<byte> _x1Arr;
        OTExtensionBristolSender & _baseOTSender;
        COTSK_Prg _prg;
    
};


class COTSK_ReceiverSession {
    public:
        COTSK_ReceiverSession(OTExtensionBristolSender & baseOTSender,
                              const shared_ptr<CommParty> & channel,
                              uint32_t L,
                              uint32_t maxExpandBits) : _L(L), _maxExpandBits(maxExpandBits),_OThandler(baseOTSender,L) , _extendHandler(channel,L,maxExpandBits)
        {
        }
    
        void initializeOrRekey() {
            _OThandler.initializeOrRekey();
            _extendHandler.keyPrg(_OThandler.getK0(), _OThandler.getK1());
        }
    
        void extend (uint32_t size_bits,  const byte *x_and_r, byte *t_j_i_out) {
            _extendHandler.extend(size_bits,x_and_r,t_j_i_out);
        }
    
    private:
    
        uint32_t _L;
        uint32_t _maxExpandBits;
        COTSK_ReceiverSessionOTHandler _OThandler;
        COTSK_ReceiverSessionExtendHandler _extendHandler;
     
};

class COTSK_Receiver {
	public:
	
		COTSK_Receiver(int baseOTport,  const shared_ptr<CommParty> & channel , uint32_t L, uint8_t numSessions, uint32_t maxExpandBits) : 
            _baseOTSender(baseOTport,true,channel) {
                                                    
            _sessions.resize(numSessions);
             for (uint8_t i=0; i < numSessions; i++) {
               _sessions[i] = new COTSK_ReceiverSession(_baseOTSender, channel,L,maxExpandBits);              
            }
        }
	
		void initializeOrRekey(uint8_t sessionId) {
            _sessions[sessionId]->initializeOrRekey();
        }
	
		void extend(uint8_t sessionId, uint32_t size_bits, const byte *x_and_r, byte *t_j_i_out) {
            _sessions[sessionId]->extend(size_bits,x_and_r,t_j_i_out);
        }
				
	private:
        OTExtensionBristolSender _baseOTSender;
		vector< COTSK_ReceiverSession *> _sessions;
};



#endif // COTSHORTKEYS_H___