#include "COTSK.h"
#define DEBUG_PRINT

/**
* Test Program for the OT functionality with shorty keys
* This is the only file that needs to be included and used directly 
* See COTSK.h for documentation on the protocol
*
* Written by: Assi Barak, April 2018
*/
#include "args.hxx"

#include <cryptoTools/Common/MatrixView.h>
#include "../../install/include/libOTe/libOTe/Tools/Tools.h"

void unit_test_transpose() {
	
	byte vec1[16] =  {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xEE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	byte vec2[16];
	byte vec3[16];

	osuCrypto::MatrixView<osuCrypto::u8> m1(vec1,8,2);
	osuCrypto::MatrixView<osuCrypto::u8> m2(vec2,16,1);
    osuCrypto::MatrixView<osuCrypto::u8> m3(vec3,8,2);
		
	osuCrypto::sse_transpose(m1,m2);
	osuCrypto::sse_transpose(m2,m3);
	
	cout << hex;
    for (int i=0; i < 16; i++) {
		cout << (int)vec1[i] << " " << (int)vec2[i]  << " " <<  (int)vec3[i] << endl;
	}
	cout << dec;

}


int main(int argc, char *argv[]) {
	
	/*
	* Parse command line - get Party Id. (0,...)
	*/
	
	args::ArgumentParser parser("This is a test program.", "This goes after the options.");
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
	args::ValueFlag<int> arg_partyId(parser, "partyId", "Id of the local party", {'p'});	
	args::ValueFlag<long> arg_numPartyOne(parser, "numPartyOne", "number of parties in P1 commitee", {"np1"}, 1);	
	args::ValueFlag<long> arg_numPartyTwo(parser, "numPartyTwo", "number of parties in P2 commitee", {"np2"}, 1);	
	args::ValueFlag<uint32_t> arg_l(parser, "L", "Short key length ", {'l'}, 8);	
	args::ValueFlag<uint32_t> arg_mBytes(parser, "mBytes", "M size (in bytes) for extend test", {'m'}, 2048);	
 	args::ValueFlag<uint32_t> arg_maxBytes(parser, "maxBytes", "Max M size (in bytes) for extend test", {"max"}, 1024*10*2);	
  	args::ValueFlag<long> arg_repeat(parser, "repeat", "Number of timer extend is repeated ", {'r'}, 1);	
  	args::ValueFlag<long> arg_sessions(parser, "sessions", "Number of sessions ", {'s'}, 1);	
  	args::ValueFlag<long> arg_rekeys(parser, "rekey", "Number of rekeys - calls to initialize. ", {'k'}, 1);	
  	args::CompletionFlag completion(parser, {"complete"});
    try
    {
        parser.ParseCLI(argc, argv);
    }
    catch (args::Completion e)
    {
        std::cout << e.what();
        return 0;
    }
    catch (args::Help)
    {
        std::cout << parser;
        return 0;
    }
    catch (args::ParseError e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    }
	
	//unit_test_transpose();
	
	int my_num =  args::get(arg_partyId);
	uint32_t L = args::get(arg_l);
	assert(L == 8 || L == 16 || L == 32);
	
    uint32_t m_bytes = args::get(arg_mBytes);
	assert(m_bytes % 16 == 0);

	uint32_t m_maxBytes = args::get(arg_maxBytes);
	assert(m_maxBytes % 16 == 0);
	
	int REPEAT_EXTEND = args::get(arg_repeat);
	int numSessions = args::get(arg_sessions);
	int numRekey = args::get(arg_rekeys);
	/*
	* Number of parties in each grCommitee. By default this is set to 2 and 2
	* When running the progam, the party Id should be passed as a paramesize_tter
	* parties 0, 1 will be in Commitee_P1 , and parties 2 and 3 in Commitee_P2
	*/
    int NUM_P1 = args::get(arg_numPartyOne);
	int NUM_P2 = args::get(arg_numPartyTwo);
	assert(NUM_P1 + NUM_P2 <= 100);
	/*
	* Peer IPs. Default uses localhost for all parties 
	*/
	vector<string> p1ips(NUM_P1,"127.0.0.1");
    vector<string> p2ips(NUM_P2,"127.0.0.1");

	/*
	 * Parties in Committee 1. Instantiate a COTSK_pOne object 
	*/
 	if (my_num < NUM_P1 ) { //pOne
		
			// Allocate a buffer for the results
			byte * working_buff = (byte *) _mm_malloc(p2ips.size()*L*m_bytes , 16);

			// Create a handler object for all the peers 
			auto p1 = new COTSK_pOne(L, 2, m_maxBytes*8, my_num ,"127.0.0.1" ,p2ips);
		
		    // Create test input of 0x0101010 for test
		    vector<byte> delta(L/8);
			for (uint32_t i=0; i < L/8; i++) {
				delta[i] = 0x55; 
			}
			cout << "first byte of delta " << hex << (int) delta[0] << endl;
		
			auto start = scapi_now();
		
		    // extenral loop is on number of rekeys, to test that rekeying (running ot) works
			for (int rekey=0; rekey < numRekey; rekey++)
			{
				//loop on sessions - in practice their are two wehn used in the protcol
			    //The test program uses same size in both cases, however different sizes can be used
				for (int session =0; session < numSessions; session++) {
					p1->initializeOrRekey(session,delta.data());
					print_elapsed_ms(start, "initialize ");
				}
				// the output is written into a list of buffers. We initialize will all buffers pointing
				// to differnet placesin the same buffer
				vector<byte *> q_i_j(p2ips.size());
				for (uint32_t i=0; i < p2ips.size(); i++) {
					q_i_j[i] = working_buff + i*(L*m_bytes) ;
				}
				start = scapi_now();

				for (int session =0; session < numSessions; session++) {
					for (int i = 0; i < REPEAT_EXTEND; i++) {
						p1->extend (session, m_bytes*8 , q_i_j);
						}
					print_elapsed_ms(start, "extend ");
				}
				cout << "first byte of q_i_j " << hex << (int) (*(q_i_j[0])) << endl;
				
			}
    }
	/*
     * Parties in Committee 2. Instantiate a COTSK_pTwo object 
	 */
	else if (my_num <= NUM_P1 + NUM_P2) { //pTwo
		byte * working_buff = (byte *) _mm_malloc(p1ips.size()*L*m_bytes , 16);
		auto p2 = new COTSK_pTwo(L, 2, m_maxBytes*8, my_num-NUM_P1, "127.0.0.1", p1ips);
		auto start = scapi_now();
		
		for (int rekey=0; rekey < numRekey; rekey++){
			
			for (int session =0; session < numSessions; session++) {
				p2->initializeOrRekey(session);  		
				print_elapsed_ms(start, "initialize ");
			}
		
			cout << dec;
  		    vector<byte> x(m_bytes,0);
 			vector<byte *> t_j_i_out(p1ips.size());
			for (uint32_t i=0; i < p2ips.size(); i++) {
				t_j_i_out[i] = working_buff + i*(L*m_bytes);
			}
		
			start = scapi_now();
			for (int session =0; session < numSessions; session++) {
				for (int i = 0; i < REPEAT_EXTEND; i++) {
					p2->extend(session, m_bytes*8 , x.data() , t_j_i_out);
				}
		    }
		    print_elapsed_ms(start, "extend ");
			cout << "first byte of tj " << hex << (int) (*(t_j_i_out[0])) << endl;
			cout << "first byte of x "  << hex << (int) x[0] << endl;
		
		}		
    }
}
