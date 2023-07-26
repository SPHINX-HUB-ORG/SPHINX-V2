/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
*
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/


#pragma once

#include <string>
#include <map>
#include <iostream>
#include <vector>
#include <utility>
#include <algorithm>
#include "../infra/Measurement.hpp"
#include "../comm/MPCCommunication.hpp"

using namespace std;

class CmdParser {
public:
    string getKey(const string & parameter);
    vector<pair<string, string>> parseArguments(string protocolName, int argc, char* argv[]);
    string getValueByKey(vector<pair<string, string>>arguments, string key);
};

/**
 * This class is an abstract class for all kinds of protocols.
 * Since the protocols are different from each other, the only function that common is the run function that executes
 * the protocol.
 *
 * In order to run a protocol one should follow the next steps:
 * 1. Create the protocol. Give all the protocol's parameters to the constructor.
 * 2. In case the protocols needs input, call setInput function.
 * 3. Call run function.
 *
 * The setInput function is not part of this abstract class since:
 * 1. Not all the protocols has input.
 * 2. Every protocol ges different input.
 */
class Protocol {

private:
    CmdParser parser;
protected:
    vector<pair<string, string>> arguments;
    Measurement* timer;

public:
    Protocol(string protocolName, int argc, char* argv[]);

    /**
     * Executes the protocol.
     */
    virtual void run() = 0;
    virtual bool hasOffline() = 0;
    virtual void runOffline(){};
    virtual bool hasOnline() = 0;
    virtual void runOnline(){};
    vector<pair<string, string>> getArguments();
    CmdParser getParser();

    virtual ~Protocol() {}
};

class MPCProtocol : public Protocol{

private:

    void initTimes();
    void exchangeDataSameInput(byte* sendData, byte* receiveData, int first, int last, int msgSize);
    void exchangeDataDiffInput(byte* sendData, byte* receiveData, int first, int last, int msgSize);
protected:

    MPCCommunication comm;
    vector<shared_ptr<CommParty>> parties;

    int partyID;
    int numParties;
    int times; //Number of times to execute the protocol
    int currentIteration; //The current execution number
    int numThreads, numPartiesForEachThread;

public:
    MPCProtocol(string protocolName, int argc, char* argv[], bool initComm = true);
    ~MPCProtocol();

    void run();

    /**
     * This function sends the same message to all the other parties and receive data from all the other parties.
     * All messages are in the same size.
     * The sendData array contains the message that should be sent to all the other parties.
     * The receiveData array will be filled with all the messages that the other parties sent to this party, ordered by the party id index.
     */
    void roundFunctionSameMsg(byte* sendData, byte* receiveData, size_t msgSize);

    /**
     * This function sends a unique message to each one of the other parties and receive data from all the other parties.
     * All messages are in the same size.
     * The sendData array contains a message for each one of the other parties, ordered by the party id index.
     * The receiveData array will be filled with all the messages that the other parties sent to this party, ordered by the party id index.
     */
    void roundFunctionDiffMsg(byte* sendData, byte* receiveData, int msgSize);


};
